'use strict';

jest.mock('axios');
const axios = require('axios');
const { enrichWithVT } = require('../lib/virustotal');

const ORIGINAL_ENV = process.env;

beforeEach(() => {
  jest.resetAllMocks();
  process.env = { ...ORIGINAL_ENV, VIRUSTOTAL_API_KEY: 'test-vt-key' };
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

const mockVTResponse = (stats = {}, extra = {}) => ({
  data: {
    data: {
      attributes: {
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          ...stats
        },
        last_analysis_date: 1700000000,
        tags: [],
        ...extra
      }
    }
  }
});

describe('enrichWithVT', () => {
  describe('API key handling', () => {
    test('returns queried:false when API key not configured', async () => {
      process.env.VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here';
      const result = await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.queried).toBe(false);
      expect(result.error).toMatch(/not configured/i);
    });

    test('returns queried:false when API key is empty', async () => {
      process.env.VIRUSTOTAL_API_KEY = '';
      const result = await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.queried).toBe(false);
    });
  });

  describe('SHA256 hash lookup', () => {
    test('calls /files endpoint for sha256', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse({ malicious: 5 }));
      const hash = 'a'.repeat(64);
      const result = await enrichWithVT({ value: hash, type: 'sha256' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining(`/files/${hash}`),
        expect.any(Object)
      );
      expect(result.source).toBe('virustotal');
      expect(result.queried).toBe(true);
      expect(result.error).toBeNull();
      expect(result.data.malicious).toBe(5);
      expect(result.data.found).toBe(true);
    });
  });

  describe('SHA1 hash lookup', () => {
    test('calls /files endpoint for sha1', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse());
      const hash = 'b'.repeat(40);
      await enrichWithVT({ value: hash, type: 'sha1' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/files/'),
        expect.any(Object)
      );
    });
  });

  describe('MD5 hash lookup', () => {
    test('calls /files endpoint for md5', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse());
      const hash = 'c'.repeat(32);
      await enrichWithVT({ value: hash, type: 'md5' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/files/'),
        expect.any(Object)
      );
    });
  });

  describe('IPv4 lookup', () => {
    test('calls /ip_addresses endpoint for ipv4', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse({ malicious: 2 }, { country: 'RU' }));
      const result = await enrichWithVT({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/ip_addresses/1.2.3.4'),
        expect.any(Object)
      );
      expect(result.data.country).toBe('RU');
    });
  });

  describe('Domain lookup', () => {
    test('calls /domains endpoint for domain', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse());
      await enrichWithVT({ value: 'evil.com', type: 'domain' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/domains/evil.com'),
        expect.any(Object)
      );
    });
  });

  describe('URL lookup', () => {
    test('calls /urls endpoint for url with base64url id', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse());
      const url = 'https://evil.com/path';
      await enrichWithVT({ value: url, type: 'url' });
      const expectedId = Buffer.from(url).toString('base64url');
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining(`/urls/${expectedId}`),
        expect.any(Object)
      );
    });
  });

  describe('error handling', () => {
    test('returns found:false for 404 response', async () => {
      const err = new Error('Not Found');
      err.response = { status: 404 };
      axios.get.mockRejectedValueOnce(err);
      const result = await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.data.found).toBe(false);
      expect(result.error).toBeNull();
    });

    test('throws for 429 rate limit response so queue can retry', async () => {
      const err = new Error('Too Many Requests');
      err.response = { status: 429 };
      axios.get.mockRejectedValueOnce(err);
      await expect(enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' })).rejects.toThrow();
    });

    test('returns error for other HTTP errors (500)', async () => {
      const err = new Error('Server Error');
      err.response = { status: 500 };
      axios.get.mockRejectedValueOnce(err);
      const result = await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.error).toMatch(/500/);
      expect(result.queried).toBe(true);
    });

    test('returns error for network failure', async () => {
      axios.get.mockRejectedValueOnce(new Error('Network timeout'));
      const result = await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.error).toMatch(/timeout/i);
      expect(result.queried).toBe(true);
    });

    test('returns queried:false for unsupported IOC type', async () => {
      const result = await enrichWithVT({ value: 'unknown', type: 'unknown_type' });
      expect(result.queried).toBe(false);
    });
  });

  describe('response normalization', () => {
    test('normalizes analysis stats correctly', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse({
        malicious: 10,
        suspicious: 2,
        harmless: 50,
        undetected: 5
      }));
      const result = await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.data.malicious).toBe(10);
      expect(result.data.suspicious).toBe(2);
      expect(result.data.harmless).toBe(50);
      expect(result.data.undetected).toBe(5);
      expect(result.data.total).toBe(67);
    });

    test('includes lastSeen as ISO string when last_analysis_date present', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse({}, { last_analysis_date: 1700000000 }));
      const result = await enrichWithVT({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.lastSeen).toBeTruthy();
      expect(new Date(result.data.lastSeen).toISOString()).toBe(result.data.lastSeen);
    });

    test('sets x-apikey header', async () => {
      axios.get.mockResolvedValueOnce(mockVTResponse());
      await enrichWithVT({ value: 'a'.repeat(64), type: 'sha256' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ 'x-apikey': 'test-vt-key' })
        })
      );
    });
  });
});
