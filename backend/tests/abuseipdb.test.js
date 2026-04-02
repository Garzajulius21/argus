'use strict';

jest.mock('axios');
const axios = require('axios');
const { enrichWithAbuseIPDB } = require('../lib/abuseipdb');

const ORIGINAL_ENV = process.env;

beforeEach(() => {
  jest.resetAllMocks();
  process.env = { ...ORIGINAL_ENV, ABUSEIPDB_API_KEY: 'test-abuse-key' };
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

const mockAbuseResponse = (overrides = {}) => ({
  data: {
    data: {
      abuseConfidenceScore: 0,
      totalReports: 0,
      lastReportedAt: null,
      countryCode: null,
      isp: null,
      domain: null,
      ...overrides
    }
  }
});

describe('enrichWithAbuseIPDB', () => {
  describe('type filtering', () => {
    test('skips enrichment for sha256 type', async () => {
      const result = await enrichWithAbuseIPDB({ value: 'a'.repeat(64), type: 'sha256' });
      expect(result.queried).toBe(false);
      expect(result.error).toBeNull();
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('skips enrichment for sha1 type', async () => {
      const result = await enrichWithAbuseIPDB({ value: 'a'.repeat(40), type: 'sha1' });
      expect(result.queried).toBe(false);
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('skips enrichment for md5 type', async () => {
      const result = await enrichWithAbuseIPDB({ value: 'a'.repeat(32), type: 'md5' });
      expect(result.queried).toBe(false);
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('skips enrichment for domain type', async () => {
      const result = await enrichWithAbuseIPDB({ value: 'evil.com', type: 'domain' });
      expect(result.queried).toBe(false);
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('skips enrichment for url type', async () => {
      const result = await enrichWithAbuseIPDB({ value: 'https://evil.com', type: 'url' });
      expect(result.queried).toBe(false);
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('queries only for ipv4 type', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse());
      await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledTimes(1);
    });
  });

  describe('API key handling', () => {
    test('returns queried:false when API key is placeholder', async () => {
      process.env.ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key_here';
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(false);
      expect(result.error).toMatch(/not configured/i);
    });

    test('returns queried:false when API key is empty', async () => {
      process.env.ABUSEIPDB_API_KEY = '';
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(false);
    });
  });

  describe('successful enrichment', () => {
    test('calls correct AbuseIPDB endpoint', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse());
      await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/check'),
        expect.any(Object)
      );
    });

    test('sends correct params', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse());
      await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          params: expect.objectContaining({
            ipAddress: '1.2.3.4',
            maxAgeInDays: 90
          })
        })
      );
    });

    test('sets Key header with API key', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse());
      await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ 'Key': 'test-abuse-key' })
        })
      );
    });

    test('maps abuseScore correctly', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse({ abuseConfidenceScore: 85 }));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.abuseScore).toBe(85);
    });

    test('maps totalReports correctly', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse({ totalReports: 47 }));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.totalReports).toBe(47);
    });

    test('maps country from countryCode', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse({ countryCode: 'CN' }));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.country).toBe('CN');
    });

    test('maps lastSeen from lastReportedAt', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse({ lastReportedAt: '2024-01-15T10:00:00Z' }));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.lastSeen).toBe('2024-01-15T10:00:00Z');
    });

    test('sets found:true when totalReports > 0', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse({ totalReports: 5 }));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.found).toBe(true);
    });

    test('sets found:false when totalReports = 0', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse({ totalReports: 0 }));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.found).toBe(false);
    });

    test('returns source:abuseipdb', async () => {
      axios.get.mockResolvedValueOnce(mockAbuseResponse());
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.source).toBe('abuseipdb');
    });
  });

  describe('error handling', () => {
    test('returns error for HTTP error response', async () => {
      const err = new Error('Unauthorized');
      err.response = { status: 401 };
      axios.get.mockRejectedValueOnce(err);
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.error).toMatch(/401/);
      expect(result.queried).toBe(true);
    });

    test('returns error for network failure', async () => {
      axios.get.mockRejectedValueOnce(new Error('Connection refused'));
      const result = await enrichWithAbuseIPDB({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.error).toMatch(/Connection refused/i);
      expect(result.queried).toBe(true);
    });
  });
});
