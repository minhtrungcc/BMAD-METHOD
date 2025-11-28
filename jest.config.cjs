module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.js', '**/*.test.js'],
  collectCoverageFrom: [
    'tools/**/*.js',
    '!tools/**/__tests__/**',
    '!tools/**/node_modules/**',
    '!tools/cli.js',
    '!tools/bmad-npx-wrapper.js',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  verbose: true,
};
