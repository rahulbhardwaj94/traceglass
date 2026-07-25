// Flat config (ESLint 9). Run with `npm run lint`.
//
// Layering, and why:
//   - Shipped TypeScript (packages/*/src, excluding tests) gets FULL type-aware
//     linting. That is the code published to npm; it handles evidence, signing,
//     and the read auth gate, so it earns the expensive rules.
//   - Tests and build configs sit outside every tsconfig `include` (deliberately
//     - they must not compile into dist), so type-aware rules cannot run on them
//     without inventing a lint-only tsconfig. They get the syntactic ruleset.
//   - Plain .mjs scripts get the JS recommended set only.
//
// NOTE ON WARNINGS: `npm run lint` exits 0 today. The rules in the
// "promoteToError" block below are real and currently violated by existing
// source; they are set to 'warn' so the debt stays visible instead of being
// deleted outright. Fix the call sites, then flip each to 'error'. Do not add
// new violations - the warning count should trend to zero, not grow.

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

/**
 * Rules that are genuinely valuable but have pre-existing violations in source.
 * Counts are as of the v0.8 lint introduction. Promote each to 'error' once its
 * call sites are fixed.
 */
const promoteToError = {
  // 5 violations (cli/src/bin.ts x3, web/App.tsx, web/SessionPicker.tsx).
  // HIGH VALUE: an unhandled rejection in the CLI can exit 0 on a failed verify.
  '@typescript-eslint/no-floating-promises': 'warn',

  // 2 violations (web/App.tsx:64, web/SessionPicker.tsx:120).
  // HIGH VALUE: async handlers passed where void is expected swallow errors.
  '@typescript-eslint/no-misused-promises': 'warn',

  // 2 violations (core/report/html.ts:179, web/format.ts:68). Both are a
  // deliberate String(value) fallback in a catch after JSON.stringify throws on
  // a circular ref. Low severity, but "[object Object]" in an audit report is
  // still a bad look.
  '@typescript-eslint/no-base-to-string': 'warn',

  // 6 violations. Pure cleanup, no bug risk.
  '@typescript-eslint/no-unnecessary-type-assertion': 'warn',

  // 5 violations. Mostly interface-conformance async methods. Stylistic.
  '@typescript-eslint/require-await': 'warn',

  // 2 violations (core/journal.ts:4 unused import, core/live.test.ts:95).
  '@typescript-eslint/no-unused-vars': [
    'warn',
    { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
  ],

  // 1 violation. Trivial.
  'prefer-const': 'warn',
};

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'fixtures/**'] },

  // ---------------------------------------------------------------------------
  // Shipped TypeScript sources - type-aware.
  // ---------------------------------------------------------------------------
  {
    files: ['packages/*/src/**/*.{ts,tsx}'],
    ignores: ['**/*.test.ts', '**/*.test.tsx'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      ...promoteToError,

      // U+2009 THIN SPACE is used deliberately in formatted output, between a
      // number and its unit in durations (see packages/web/src/format.ts), so
      // allow it inside templates and strings while still catching stray
      // invisible characters in actual code.
      'no-irregular-whitespace': ['error', { skipStrings: true, skipTemplates: true }],
    },
  },

  // React dashboard: hook correctness (stale closures / missing deps are real bugs).
  {
    files: ['packages/web/src/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      // One acknowledged opt-out already exists in web/src/hooks/useTween.ts.
      'react-hooks/exhaustive-deps': 'warn',
    },
    languageOptions: {
      globals: { ...globals.browser },
    },
  },

  // ---------------------------------------------------------------------------
  // Tests + build configs - syntactic only (no tsconfig covers these files).
  // ---------------------------------------------------------------------------
  {
    files: ['packages/**/*.test.{ts,tsx}', 'packages/*/vite.config.ts', 'vitest.config.ts'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      globals: { ...globals.node },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
    },
  },

  // ---------------------------------------------------------------------------
  // Plain ESM scripts (build helpers, the e2e outcome check).
  // ---------------------------------------------------------------------------
  {
    files: ['scripts/**/*.mjs', 'packages/*/scripts/**/*.mjs', '*.mjs'],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.node },
    },
  },
);
