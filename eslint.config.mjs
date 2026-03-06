import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    {
        rules: {
            // Type safety — zero tolerance
            '@typescript-eslint/no-explicit-any': 'error',
            '@typescript-eslint/explicit-function-return-type': ['error', {
                allowExpressions: true,
                allowHigherOrderFunctions: true,
                allowConciseArrowFunctionExpressionsStartingWithVoid: true,
            }],
            '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
            '@typescript-eslint/no-non-null-assertion': 'error',
            '@typescript-eslint/no-unsafe-assignment': 'off',
            '@typescript-eslint/prefer-readonly': 'off',
            '@typescript-eslint/consistent-type-imports': ['error', {
                prefer: 'type-imports',
                fixStyle: 'inline-type-imports',
            }],

            // Security — we are a security tool
            'no-eval': 'error',
            'no-implied-eval': 'error',
            'no-new-func': 'error',
            'no-script-url': 'error',

            // Code quality
            'no-console': ['warn', { allow: ['warn', 'error'] }],
            'no-debugger': 'error',
            'no-duplicate-imports': 'off', // Handled by @typescript-eslint/consistent-type-imports
            'no-throw-literal': 'error',
            'prefer-const': 'error',
            'no-var': 'error',
            'eqeqeq': ['error', 'always'],
            'curly': ['error', 'all'],
            'no-return-await': 'error',
            'require-await': 'warn', // Lifecycle hooks are intentionally async for overridability
        },
    },
    // CLI files need console.log for user-facing output
    {
        files: ['src/cli/**/*.ts', 'src/reporters/**/*.ts'],
        rules: {
            'no-console': 'off',
        },
    },
    {
        ignores: ['dist/**', 'node_modules/**'],
    }
);
