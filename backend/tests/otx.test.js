'use strict';

jest.mock('axios');
const axios = require('axios');
const { enrichWithOTX } = require('../lib/otx');

const ORIGINAL_ENV = process.env;

beforeEach(() => {
  jest.resetAllMocks();
  process.env = { ...ORIGINAL_ENV, OTX_API_KEY: 'test-otx-key' };
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

function mockOTXResponse(pulseCount = 0, pulses = []) {
  return {
    data: {
      pulse_info: {
        count: pulseCount,
        pulses
      }
    }
  };
}

function makePulse(overrides = {}) {
  return {
    tags: [],
    adversary: null,
    malware_families: [],
    attack_ids: [],
    ...overrides
  };
}

describe('enrichWithOTX', () => {
  describe('API key handling', () => {
    test('returns queried:false when API key is missing', async () => {
      delete process.env.OTX_API_KEY;
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(false);
      expect(result.error).toMatch(/not configured/i);
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('returns queried:false when API key is placeholder', async () => {
      process.env.OTX_API_KEY = 'your_otx_api_key_here';
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(false);
      expect(result.error).toMatch(/not configured/i);
      expect(axios.get).not.toHaveBeenCalled();
    });

    test('returns queried:false when API key is empty string', async () => {
      process.env.OTX_API_KEY = '';
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(false);
      expect(axios.get).not.toHaveBeenCalled();
    });
  });

  describe('IOC type routing', () => {
    test('queries IPv4 under IPv4 endpoint', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('IPv4/1.2.3.4/general'),
        expect.any(Object)
      );
    });

    test('queries domain under domain endpoint', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: 'evil.com', type: 'domain' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('domain/evil.com/general'),
        expect.any(Object)
      );
    });

    test('queries url under url endpoint', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: 'https://evil.com/path', type: 'url' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('url/'),
        expect.any(Object)
      );
    });

    test('queries md5 under file endpoint', async () => {
      const hash = 'a'.repeat(32);
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: hash, type: 'md5' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining(`file/${hash}/general`),
        expect.any(Object)
      );
    });

    test('queries sha1 under file endpoint', async () => {
      const hash = 'b'.repeat(40);
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: hash, type: 'sha1' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining(`file/${hash}/general`),
        expect.any(Object)
      );
    });

    test('queries sha256 under file endpoint', async () => {
      const hash = 'c'.repeat(64);
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: hash, type: 'sha256' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining(`file/${hash}/general`),
        expect.any(Object)
      );
    });

    test('sends X-OTX-API-KEY header', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse());
      await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(axios.get).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ 'X-OTX-API-KEY': 'test-otx-key' })
        })
      );
    });
  });

  describe('zero pulses', () => {
    test('returns found:false when pulseCount is 0', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse(0, []));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(true);
      expect(result.data.found).toBe(false);
      expect(result.data.pulseCount).toBe(0);
    });

    test('returns empty arrays when no pulses', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse(0, []));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.tags).toEqual([]);
      expect(result.data.adversaries).toEqual([]);
      expect(result.data.malwareFamilies).toEqual([]);
      expect(result.data.attackIds).toEqual([]);
    });
  });

  describe('pulse data aggregation', () => {
    test('returns found:true when pulseCount > 0', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse(2, [makePulse(), makePulse()]));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.found).toBe(true);
      expect(result.data.pulseCount).toBe(2);
    });

    test('aggregates tags from multiple pulses and lowercases them', async () => {
      const pulses = [
        makePulse({ tags: ['Ransomware', 'C2'] }),
        makePulse({ tags: ['phishing', 'C2'] })
      ];
      axios.get.mockResolvedValueOnce(mockOTXResponse(2, pulses));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.tags).toContain('ransomware');
      expect(result.data.tags).toContain('c2');
      expect(result.data.tags).toContain('phishing');
      expect(result.data.tags.length).toBe(3); // deduped
    });

    test('aggregates adversaries from multiple pulses', async () => {
      const pulses = [
        makePulse({ adversary: 'APT28' }),
        makePulse({ adversary: 'APT29' }),
        makePulse({ adversary: 'APT28' }) // duplicate
      ];
      axios.get.mockResolvedValueOnce(mockOTXResponse(3, pulses));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.adversaries).toContain('APT28');
      expect(result.data.adversaries).toContain('APT29');
      expect(result.data.adversaries.length).toBe(2); // deduped
    });

    test('aggregates malware families from multiple pulses', async () => {
      const pulses = [
        makePulse({ malware_families: [{ display_name: 'Emotet' }, { display_name: 'TrickBot' }] }),
        makePulse({ malware_families: [{ display_name: 'Emotet' }] }) // duplicate
      ];
      axios.get.mockResolvedValueOnce(mockOTXResponse(2, pulses));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.malwareFamilies).toContain('Emotet');
      expect(result.data.malwareFamilies).toContain('TrickBot');
      expect(result.data.malwareFamilies.length).toBe(2); // deduped
    });

    test('aggregates MITRE ATT&CK IDs from multiple pulses', async () => {
      const pulses = [
        makePulse({ attack_ids: [{ id: 'T1059' }, { id: 'T1566' }] }),
        makePulse({ attack_ids: [{ id: 'T1059' }] }) // duplicate
      ];
      axios.get.mockResolvedValueOnce(mockOTXResponse(2, pulses));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.attackIds).toContain('T1059');
      expect(result.data.attackIds).toContain('T1566');
      expect(result.data.attackIds.length).toBe(2); // deduped
    });

    test('caps tags at 10', async () => {
      const tags = Array.from({ length: 15 }, (_, i) => `tag${i}`);
      axios.get.mockResolvedValueOnce(mockOTXResponse(1, [makePulse({ tags })]));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.tags.length).toBeLessThanOrEqual(10);
    });

    test('caps adversaries at 5', async () => {
      const pulses = Array.from({ length: 8 }, (_, i) => makePulse({ adversary: `Actor${i}` }));
      axios.get.mockResolvedValueOnce(mockOTXResponse(8, pulses));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.adversaries.length).toBeLessThanOrEqual(5);
    });

    test('ignores null adversary values', async () => {
      const pulses = [makePulse({ adversary: null }), makePulse({ adversary: 'APT1' })];
      axios.get.mockResolvedValueOnce(mockOTXResponse(2, pulses));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.adversaries).not.toContain(null);
      expect(result.data.adversaries).toContain('APT1');
    });

    test('returns source:otx', async () => {
      axios.get.mockResolvedValueOnce(mockOTXResponse(1, [makePulse()]));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.source).toBe('otx');
    });
  });

  describe('error handling', () => {
    test('returns found:false with no error on 404', async () => {
      const err = new Error('Not Found');
      err.response = { status: 404, data: {} };
      axios.get.mockRejectedValueOnce(err);
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(true);
      expect(result.error).toBeNull();
      expect(result.data.found).toBe(false);
    });

    test('returns error message on HTTP 429', async () => {
      const err = new Error('Too Many Requests');
      err.response = { status: 429, data: {} };
      axios.get.mockRejectedValueOnce(err);
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(true);
      expect(result.error).toMatch(/429/);
    });

    test('returns error message on HTTP 401', async () => {
      const err = new Error('Unauthorized');
      err.response = { status: 401, data: {} };
      axios.get.mockRejectedValueOnce(err);
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(true);
      expect(result.error).toMatch(/401/);
    });

    test('returns error message on network failure', async () => {
      axios.get.mockRejectedValueOnce(new Error('ECONNREFUSED'));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.queried).toBe(true);
      expect(result.error).toMatch(/ECONNREFUSED/i);
    });

    test('returns empty data on any error', async () => {
      axios.get.mockRejectedValueOnce(new Error('timeout'));
      const result = await enrichWithOTX({ value: '1.2.3.4', type: 'ipv4' });
      expect(result.data.found).toBe(false);
      expect(result.data.pulseCount).toBe(0);
    });
  });
});
