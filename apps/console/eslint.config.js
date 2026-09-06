import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'public/**',
      '../api/runtime/**',
      '../../legacy/scripts/**',
      '*.config.js',
      'vite.config.js',
      'vite.config.d.ts'
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}', 'vite.config.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2020
      }
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'no-undef': 'off',
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'react-hooks/set-state-in-effect': 'warn',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/ban-ts-comment': [
        'warn',
        {
          'ts-ignore': 'allow-with-description',
          minimumDescriptionLength: 3
        }
      ],
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }]
    }
  },
  {
    files: ['scripts/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.es2020
      }
    },
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-require-imports': 'off'
    }
  }
);
