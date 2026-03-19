#!/usr/bin/env node

const surface = process.argv[2] ?? 'This surface';

console.error(
  `${surface} is unsupported in this release. Use local AgentPay SDK admin commands instead.`,
);
process.exit(1);
