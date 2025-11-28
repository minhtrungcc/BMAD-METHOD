const path = require('node:path');
const fs = require('node:fs').promises;

/**
 * Security utilities for input validation and sanitization
 */
const SecurityUtils = {
  /**
   * Validates and sanitizes a directory path to prevent path traversal attacks
   * @param {string} inputPath - The path to validate
   * @param {string} basePath - The base path that the input should be relative to
   * @returns {Object} - { valid: boolean, sanitized: string, error: string }
   */
  validatePath(inputPath, basePath = process.cwd()) {
    if (!inputPath || typeof inputPath !== 'string') {
      return {
        valid: false,
        sanitized: null,
        error: 'Path must be a non-empty string',
      };
    }

    // Trim whitespace
    const trimmed = inputPath.trim();

    if (trimmed.length === 0) {
      return {
        valid: false,
        sanitized: null,
        error: 'Path cannot be empty',
      };
    }

    // Check for null bytes (common in path traversal attacks)
    if (trimmed.includes('\0')) {
      return {
        valid: false,
        sanitized: null,
        error: 'Path contains invalid null byte',
      };
    }

    // Resolve the path to get absolute normalized path
    const resolved = path.isAbsolute(trimmed)
      ? path.normalize(trimmed)
      : path.resolve(basePath, trimmed);

    // Check for obvious path traversal patterns before resolution
    const suspiciousPatterns = [
      /\.\.[/\\]/g, // ../ or ..\
      /[/\\]\.\.[/\\]/g, // /../ or \..\
      /[/\\]\.\.$/g, // ends with /.. or \..
    ];

    const hasTraversalPattern = suspiciousPatterns.some((pattern) => pattern.test(trimmed));

    // If path contains traversal patterns, verify resolved path is still under basePath
    if (hasTraversalPattern) {
      const normalizedBase = path.normalize(basePath);
      const relative = path.relative(normalizedBase, resolved);

      // If relative path starts with .. or is absolute, it's outside basePath
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        return {
          valid: false,
          sanitized: null,
          error: 'Path attempts to traverse outside allowed directory',
        };
      }
    }

    // Check path length (prevent extremely long paths)
    if (resolved.length > 4096) {
      return {
        valid: false,
        sanitized: null,
        error: 'Path exceeds maximum length (4096 characters)',
      };
    }

    // Check for suspicious characters (control characters, etc.)
    // Allow: alphanumeric, spaces, hyphens, underscores, dots, forward/back slashes, colons (for Windows drives)
    const validPathPattern = /^[a-zA-Z0-9\s._\-/\\:]+$/;
    if (!validPathPattern.test(resolved)) {
      return {
        valid: false,
        sanitized: null,
        error: 'Path contains invalid characters',
      };
    }

    return {
      valid: true,
      sanitized: resolved,
      error: null,
    };
  },

  /**
   * Validates a version string to ensure it's in semver format
   * @param {string} version - The version string to validate
   * @returns {Object} - { valid: boolean, parsed: Array, error: string }
   */
  validateVersion(version) {
    if (!version || typeof version !== 'string') {
      return {
        valid: false,
        parsed: null,
        error: 'Version must be a non-empty string',
      };
    }

    const trimmed = version.trim();

    // Basic semver pattern: X.Y.Z where X, Y, Z are numbers
    // Also allows optional pre-release and build metadata
    const semverPattern = /^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?(?:\+([a-zA-Z0-9.-]+))?$/;
    const match = trimmed.match(semverPattern);

    if (!match) {
      return {
        valid: false,
        parsed: null,
        error: 'Version must be in semver format (X.Y.Z)',
      };
    }

    const [, major, minor, patch] = match;
    const parsed = [Number(major), Number(minor), Number(patch)];

    // Verify all parts are valid numbers
    if (parsed.some((num) => Number.isNaN(num) || num < 0)) {
      return {
        valid: false,
        parsed: null,
        error: 'Version parts must be non-negative integers',
      };
    }

    return {
      valid: true,
      parsed,
      error: null,
    };
  },

  /**
   * Sanitizes a string value to prevent injection in string replacements
   * @param {string} value - The value to sanitize
   * @param {number} maxLength - Maximum allowed length
   * @returns {Object} - { valid: boolean, sanitized: string, error: string }
   */
  sanitizeStringValue(value, maxLength = 1024) {
    if (value === null || value === undefined) {
      return {
        valid: false,
        sanitized: null,
        error: 'Value cannot be null or undefined',
      };
    }

    const stringValue = String(value);

    // Check for null bytes
    if (stringValue.includes('\0')) {
      return {
        valid: false,
        sanitized: null,
        error: 'Value contains invalid null byte',
      };
    }

    // Check length
    if (stringValue.length > maxLength) {
      return {
        valid: false,
        sanitized: null,
        error: `Value exceeds maximum length (${maxLength} characters)`,
      };
    }

    // For path-like values, check for traversal attempts
    if (stringValue.includes('..')) {
      return {
        valid: false,
        sanitized: null,
        error: 'Value contains suspicious path traversal sequence',
      };
    }

    return {
      valid: true,
      sanitized: stringValue,
      error: null,
    };
  },

  /**
   * Validates command arguments to prevent injection
   * @param {string|Array} args - The arguments to validate
   * @returns {Object} - { valid: boolean, sanitized: Array, error: string }
   */
  validateCommandArgs(args) {
    const argsArray = Array.isArray(args) ? args : [args];

    for (const arg of argsArray) {
      if (typeof arg !== 'string') {
        return {
          valid: false,
          sanitized: null,
          error: 'All arguments must be strings',
        };
      }

      // Check for null bytes
      if (arg.includes('\0')) {
        return {
          valid: false,
          sanitized: null,
          error: 'Argument contains invalid null byte',
        };
      }

      // Check for suspicious shell metacharacters
      // Note: spawn() with array args is safe from shell injection,
      // but we still want to prevent unexpected behavior
      const suspiciousChars = /[;|&$`<>]/;
      if (suspiciousChars.test(arg)) {
        return {
          valid: false,
          sanitized: null,
          error: 'Argument contains suspicious shell metacharacters',
        };
      }
    }

    return {
      valid: true,
      sanitized: argsArray,
      error: null,
    };
  },

  /**
   * Safely resolves a path and ensures it exists
   * @param {string} inputPath - The path to resolve
   * @param {string} basePath - The base path for relative paths
   * @returns {Promise<Object>} - { valid: boolean, path: string, error: string }
   */
  async safeResolve(inputPath, basePath = process.cwd()) {
    const validation = this.validatePath(inputPath, basePath);

    if (!validation.valid) {
      return {
        valid: false,
        path: null,
        error: validation.error,
      };
    }

    try {
      // Check if path exists
      await fs.access(validation.sanitized, fs.constants.F_OK);

      return {
        valid: true,
        path: validation.sanitized,
        error: null,
      };
    } catch {
      return {
        valid: false,
        path: validation.sanitized,
        error: 'Path does not exist',
      };
    }
  },

  /**
   * Compares two validated version strings
   * @param {string} v1 - First version
   * @param {string} v2 - Second version
   * @returns {number} - -1 if v1 < v2, 0 if equal, 1 if v1 > v2, null if invalid
   */
  compareVersions(v1, v2) {
    const validation1 = this.validateVersion(v1);
    const validation2 = this.validateVersion(v2);

    if (!validation1.valid || !validation2.valid) {
      console.warn(`Invalid version comparison: ${validation1.error || validation2.error}`);
      return null;
    }

    const parts1 = validation1.parsed;
    const parts2 = validation2.parsed;

    for (let index = 0; index < 3; index++) {
      if (parts1[index] > parts2[index]) return 1;
      if (parts1[index] < parts2[index]) return -1;
    }

    return 0;
  },
};

module.exports = SecurityUtils;
