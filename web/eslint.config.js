import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'

// ESLint 9 flat config: typescript-eslint recommendations plus browser and
// Node globals. The build runs tsc for type checking.
export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'playwright-report/**', 'test-results/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      // tsc already catches undeclared identifiers and understands DOM types.
      'no-undef': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },
)
