import ts from 'typescript-eslint';

export default ts.config({
  files: ['src/**/*.{ts,tsx}'],
  extends: [ts.configs.base],
  rules: {
    'no-restricted-syntax': ['error',
      { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: 'Packet-derived text renders through React text nodes only.' },
      { selector: "MemberExpression[property.name='innerHTML']", message: 'Packet-derived text renders through React text nodes only.' },
    ],
    'no-eval': 'error', 'no-new-func': 'error', 'no-implied-eval': 'error',
  },
});
