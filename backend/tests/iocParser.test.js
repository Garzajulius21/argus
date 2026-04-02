'use strict';

const { parseIOCs, MAX_IOCS } = require('../lib/iocParser');

describe('parseIOCs', () => {
  // --- Basic type detection ---
  describe('type detection', () => {
    test('detects SHA256 hash', () => {
      const result = parseIOCs('a'.repeat(64));
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('sha256');
      expect(result[0].value).toBe('a'.repeat(64));
    });

    test('detects SHA1 hash', () => {
      const result = parseIOCs('b'.repeat(40));
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('sha1');
    });

    test('detects MD5 hash', () => {
      const result = parseIOCs('c'.repeat(32));
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('md5');
    });

    test('detects IPv4 address', () => {
      const result = parseIOCs('8.8.8.8');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('ipv4');
      expect(result[0].value).toBe('8.8.8.8');
    });

    test('detects domain', () => {
      const result = parseIOCs('malicious.example.com');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('domain');
    });

    test('detects URL', () => {
      const result = parseIOCs('https://evil.com/payload.exe');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('url');
    });

    test('detects http URL', () => {
      const result = parseIOCs('http://malware.example.org/drop');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('url');
    });
  });

  // --- Mixed input ---
  describe('mixed input', () => {
    test('parses all 6 IOC types from a single blob', () => {
      const input = [
        'a'.repeat(64),               // sha256
        'b'.repeat(40),               // sha1
        'c'.repeat(32),               // md5
        '8.8.8.8',                    // ipv4
        'malicious.example.com',      // domain
        'https://evil.com/path'       // url
      ].join('\n');
      const result = parseIOCs(input);
      expect(result).toHaveLength(6);
      const types = result.map(r => r.type);
      expect(types).toContain('sha256');
      expect(types).toContain('sha1');
      expect(types).toContain('md5');
      expect(types).toContain('ipv4');
      expect(types).toContain('domain');
      expect(types).toContain('url');
    });
  });

  // --- Defanging ---
  describe('defanged input normalization', () => {
    test('normalizes hxxp:// to http://', () => {
      const result = parseIOCs('hxxp://evil.com/payload');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('url');
      expect(result[0].value).toBe('http://evil.com/payload');
    });

    test('normalizes hxxps:// to https://', () => {
      const result = parseIOCs('hxxps://evil.com/payload');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('url');
      expect(result[0].value).toBe('https://evil.com/payload');
    });

    test('normalizes [.] to . in domains', () => {
      const result = parseIOCs('evil[.]example[.]com');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('domain');
      expect(result[0].value).toBe('evil.example.com');
    });

    test('normalizes [dot] to . in domains', () => {
      const result = parseIOCs('malware[dot]example[dot]org');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('domain');
      expect(result[0].value).toBe('malware.example.org');
    });

    test('normalizes [.] in IP addresses', () => {
      const result = parseIOCs('8[.]8[.]8[.]8');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('ipv4');
      expect(result[0].value).toBe('8.8.8.8');
    });

    test('normalizes hxxps in URL with [.] in domain', () => {
      const result = parseIOCs('hxxps://evil[.]com/path');
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('url');
      expect(result[0].value).toBe('https://evil.com/path');
    });
  });

  // --- Private IP exclusion ---
  describe('private IP exclusion', () => {
    test('excludes 10.x.x.x range', () => {
      expect(parseIOCs('10.0.0.1')).toHaveLength(0);
      expect(parseIOCs('10.255.255.255')).toHaveLength(0);
    });

    test('excludes 172.16.x.x - 172.31.x.x range', () => {
      expect(parseIOCs('172.16.0.1')).toHaveLength(0);
      expect(parseIOCs('172.31.255.255')).toHaveLength(0);
    });

    test('does NOT exclude 172.15.x.x (outside private range)', () => {
      expect(parseIOCs('172.15.0.1')).toHaveLength(1);
    });

    test('does NOT exclude 172.32.x.x (outside private range)', () => {
      expect(parseIOCs('172.32.0.1')).toHaveLength(1);
    });

    test('excludes 192.168.x.x range', () => {
      expect(parseIOCs('192.168.0.1')).toHaveLength(0);
      expect(parseIOCs('192.168.100.200')).toHaveLength(0);
    });

    test('excludes 127.x.x.x loopback range', () => {
      expect(parseIOCs('127.0.0.1')).toHaveLength(0);
      expect(parseIOCs('127.1.2.3')).toHaveLength(0);
    });

    test('allows public IPs through', () => {
      expect(parseIOCs('8.8.8.8')).toHaveLength(1);
      expect(parseIOCs('1.1.1.1')).toHaveLength(1);
      expect(parseIOCs('45.33.32.156')).toHaveLength(1);
    });
  });

  // --- Deduplication ---
  describe('deduplication', () => {
    test('deduplicates identical IPs', () => {
      const result = parseIOCs('8.8.8.8 8.8.8.8 8.8.8.8');
      expect(result).toHaveLength(1);
    });

    test('deduplicates identical domains', () => {
      const result = parseIOCs('evil.com evil.com evil.com');
      expect(result).toHaveLength(1);
    });

    test('deduplicates case-insensitively for hashes', () => {
      const hash = 'a1b2c3d4e5f6' + '0'.repeat(20);  // 32 chars = MD5
      const result = parseIOCs(`${hash} ${hash.toUpperCase()}`);
      expect(result).toHaveLength(1);
    });

    test('keeps distinct IOCs', () => {
      const result = parseIOCs('8.8.8.8 1.1.1.1');
      expect(result).toHaveLength(2);
    });
  });

  // --- Delimiter tolerance ---
  describe('delimiter tolerance', () => {
    test('handles comma-separated IOCs', () => {
      const result = parseIOCs('8.8.8.8,1.1.1.1,45.33.32.156');
      expect(result).toHaveLength(3);
    });

    test('handles semicolon-separated IOCs', () => {
      const result = parseIOCs('8.8.8.8;1.1.1.1;45.33.32.156');
      expect(result).toHaveLength(3);
    });

    test('handles newline-separated IOCs', () => {
      const result = parseIOCs('8.8.8.8\n1.1.1.1\n45.33.32.156');
      expect(result).toHaveLength(3);
    });

    test('handles space-separated IOCs', () => {
      const result = parseIOCs('8.8.8.8 1.1.1.1 45.33.32.156');
      expect(result).toHaveLength(3);
    });

    test('handles tab-separated IOCs', () => {
      const result = parseIOCs('8.8.8.8\t1.1.1.1\t45.33.32.156');
      expect(result).toHaveLength(3);
    });

    test('handles mixed delimiters', () => {
      const result = parseIOCs('8.8.8.8,1.1.1.1; 45.33.32.156\nevil.com');
      expect(result).toHaveLength(4);
    });

    test('handles extra whitespace and blank lines', () => {
      const result = parseIOCs('  8.8.8.8  \n\n  1.1.1.1  ');
      expect(result).toHaveLength(2);
    });
  });

  // --- MAX_IOCS limit ---
  describe('IOC count limit', () => {
    test('MAX_IOCS is 100', () => {
      expect(MAX_IOCS).toBe(100);
    });

    test('enforces 100 IOC limit', () => {
      // Generate 110 unique public IPs
      const ips = [];
      for (let i = 0; i < 110; i++) {
        ips.push(`${45 + Math.floor(i / 256)}.${i % 256}.0.1`);
      }
      const result = parseIOCs(ips.join('\n'));
      expect(result.length).toBeLessThanOrEqual(100);
    });

    test('returns exactly 100 IOCs when given more than 100', () => {
      const ips = [];
      for (let i = 1; i <= 110; i++) {
        ips.push(`${200}.${Math.floor(i / 256)}.${i % 256}.1`);
      }
      const result = parseIOCs(ips.join('\n'));
      expect(result).toHaveLength(100);
    });
  });

  // --- localhost and .local exclusion ---
  describe('localhost and .local exclusion', () => {
    test('excludes localhost domain', () => {
      expect(parseIOCs('localhost')).toHaveLength(0);
    });

    test('excludes .local domains', () => {
      expect(parseIOCs('mydevice.local')).toHaveLength(0);
    });

    test('allows normal domains', () => {
      expect(parseIOCs('example.com')).toHaveLength(1);
    });
  });

  // --- Edge cases ---
  describe('edge cases', () => {
    test('returns empty array for empty string', () => {
      expect(parseIOCs('')).toHaveLength(0);
    });

    test('returns empty array for null', () => {
      expect(parseIOCs(null)).toHaveLength(0);
    });

    test('returns empty array for undefined', () => {
      expect(parseIOCs(undefined)).toHaveLength(0);
    });

    test('returns empty array for non-IOC text', () => {
      expect(parseIOCs('not an ioc at all, just some random words')).toHaveLength(0);
    });

    test('rejects octets > 255 in IPv4', () => {
      expect(parseIOCs('256.0.0.1')).toHaveLength(0);
      expect(parseIOCs('1.1.1.999')).toHaveLength(0);
    });
  });
});
