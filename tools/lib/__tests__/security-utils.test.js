const path = require('node:path');
const SecurityUtils = require('../security-utils');

describe('SecurityUtils', () => {
  describe('validatePath', () => {
    const basePath = '/home/user/project';

    test('should accept valid absolute path', () => {
      const result = SecurityUtils.validatePath('/home/user/project/subfolder', basePath);
      expect(result.valid).toBe(true);
      expect(result.sanitized).toBe(path.normalize('/home/user/project/subfolder'));
      expect(result.error).toBeNull();
    });

    test('should accept valid relative path', () => {
      const result = SecurityUtils.validatePath('subfolder', basePath);
      expect(result.valid).toBe(true);
      expect(result.sanitized).toBe(path.join(basePath, 'subfolder'));
      expect(result.error).toBeNull();
    });

    test('should reject path with null byte', () => {
      const result = SecurityUtils.validatePath('/home/user\0/project', basePath);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('null byte');
    });

    test('should reject path traversal attempt with ../', () => {
      const result = SecurityUtils.validatePath('../../etc/passwd', basePath);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('traverse outside');
    });

    test('should reject empty path', () => {
      const result = SecurityUtils.validatePath('', basePath);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('empty');
    });

    test('should reject path with only whitespace', () => {
      const result = SecurityUtils.validatePath('   ', basePath);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('empty');
    });

    test('should reject null path', () => {
      const result = SecurityUtils.validatePath(null, basePath);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('non-empty string');
    });

    test('should reject extremely long path', () => {
      const longPath = 'a'.repeat(5000);
      const result = SecurityUtils.validatePath(longPath, basePath);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('maximum length');
    });

    test('should accept path with .bmad-core', () => {
      const result = SecurityUtils.validatePath('.bmad-core', basePath);
      expect(result.valid).toBe(true);
      expect(result.sanitized).toBe(path.join(basePath, '.bmad-core'));
    });
  });

  describe('validateVersion', () => {
    test('should accept valid semver version', () => {
      const result = SecurityUtils.validateVersion('1.2.3');
      expect(result.valid).toBe(true);
      expect(result.parsed).toEqual([1, 2, 3]);
      expect(result.error).toBeNull();
    });

    test('should accept version with zeros', () => {
      const result = SecurityUtils.validateVersion('0.0.1');
      expect(result.valid).toBe(true);
      expect(result.parsed).toEqual([0, 0, 1]);
    });

    test('should reject invalid version format', () => {
      const result = SecurityUtils.validateVersion('abc.def.ghi');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('semver format');
    });

    test('should reject version with missing parts', () => {
      const result = SecurityUtils.validateVersion('1.2');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('semver format');
    });

    test('should reject version with negative numbers', () => {
      const result = SecurityUtils.validateVersion('1.-2.3');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('semver format');
    });

    test('should reject empty version', () => {
      const result = SecurityUtils.validateVersion('');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('non-empty string');
    });

    test('should reject null version', () => {
      const result = SecurityUtils.validateVersion(null);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('non-empty string');
    });

    test('should accept version with pre-release tag', () => {
      const result = SecurityUtils.validateVersion('1.2.3-alpha.1');
      expect(result.valid).toBe(true);
      expect(result.parsed).toEqual([1, 2, 3]);
    });

    test('should accept version with build metadata', () => {
      const result = SecurityUtils.validateVersion('1.2.3+build.123');
      expect(result.valid).toBe(true);
      expect(result.parsed).toEqual([1, 2, 3]);
    });
  });

  describe('sanitizeStringValue', () => {
    test('should accept valid string', () => {
      const result = SecurityUtils.sanitizeStringValue('valid-string');
      expect(result.valid).toBe(true);
      expect(result.sanitized).toBe('valid-string');
      expect(result.error).toBeNull();
    });

    test('should reject string with null byte', () => {
      const result = SecurityUtils.sanitizeStringValue('hello\0world');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('null byte');
    });

    test('should reject string exceeding max length', () => {
      const longString = 'a'.repeat(2000);
      const result = SecurityUtils.sanitizeStringValue(longString, 1024);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('maximum length');
    });

    test('should reject string with path traversal pattern', () => {
      const result = SecurityUtils.sanitizeStringValue('../etc/passwd');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('path traversal');
    });

    test('should reject null value', () => {
      const result = SecurityUtils.sanitizeStringValue(null);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('null or undefined');
    });

    test('should accept number converted to string', () => {
      const result = SecurityUtils.sanitizeStringValue(123);
      expect(result.valid).toBe(true);
      expect(result.sanitized).toBe('123');
    });
  });

  describe('validateCommandArgs', () => {
    test('should accept valid string argument', () => {
      const result = SecurityUtils.validateCommandArgs(['--input', 'file.txt']);
      expect(result.valid).toBe(true);
      expect(result.sanitized).toEqual(['--input', 'file.txt']);
    });

    test('should accept single string argument', () => {
      const result = SecurityUtils.validateCommandArgs('--help');
      expect(result.valid).toBe(true);
      expect(result.sanitized).toEqual(['--help']);
    });

    test('should reject argument with null byte', () => {
      const result = SecurityUtils.validateCommandArgs(['--input', 'file\0.txt']);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('null byte');
    });

    test('should reject argument with shell metacharacters', () => {
      const result = SecurityUtils.validateCommandArgs(['--input', 'file.txt; rm -rf /']);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('shell metacharacters');
    });

    test('should reject argument with pipe character', () => {
      const result = SecurityUtils.validateCommandArgs(['--input', 'file.txt | cat']);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('shell metacharacters');
    });

    test('should reject non-string argument', () => {
      const result = SecurityUtils.validateCommandArgs([123, 'file.txt']);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('must be strings');
    });
  });

  describe('compareVersions', () => {
    test('should return 1 when v1 > v2', () => {
      const result = SecurityUtils.compareVersions('2.0.0', '1.0.0');
      expect(result).toBe(1);
    });

    test('should return -1 when v1 < v2', () => {
      const result = SecurityUtils.compareVersions('1.0.0', '2.0.0');
      expect(result).toBe(-1);
    });

    test('should return 0 when v1 == v2', () => {
      const result = SecurityUtils.compareVersions('1.2.3', '1.2.3');
      expect(result).toBe(0);
    });

    test('should return null for invalid version strings', () => {
      const result = SecurityUtils.compareVersions('invalid', '1.2.3');
      expect(result).toBeNull();
    });

    test('should compare patch versions correctly', () => {
      const result = SecurityUtils.compareVersions('1.2.4', '1.2.3');
      expect(result).toBe(1);
    });

    test('should compare minor versions correctly', () => {
      const result = SecurityUtils.compareVersions('1.3.0', '1.2.9');
      expect(result).toBe(1);
    });
  });
});
