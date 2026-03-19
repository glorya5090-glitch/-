import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/src/lib/approval-display.ts', import.meta.url);

test('formatApprovalAmount uses built-in ERC-20 decimals and symbol', async () => {
  const display = await import(`${modulePath.href}?case=${Date.now()}-erc20`);
  const approval = {
    approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    daemonId: '11'.repeat(32),
    agentKeyId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    status: 'pending',
    reason: 'Manual approval required',
    actionType: 'transfer',
    chainId: 1,
    recipient: '0x3333333333333333333333333333333333333333',
    asset: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    amountWei: '10000000000000000000',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  assert.equal(display.formatApprovalAmount(approval), '10 USD1');
  assert.equal(display.formatApprovalAsset(approval), 'USD1');
});

test('formatApprovalAmount uses built-in native token decimals and symbol', async () => {
  const display = await import(`${modulePath.href}?case=${Date.now()}-native`);
  const approval = {
    approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    daemonId: '11'.repeat(32),
    agentKeyId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    status: 'pending',
    reason: 'Manual approval required',
    actionType: 'transfer_native',
    chainId: 56,
    recipient: '0x3333333333333333333333333333333333333333',
    asset: 'native_eth',
    amountWei: '10000000000000000',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  assert.equal(display.formatApprovalAmount(approval), '0.01 BNB');
  assert.equal(display.formatApprovalAsset(approval), 'BNB');
});

test('formatApproval display falls back to raw values for unknown assets', async () => {
  const display = await import(`${modulePath.href}?case=${Date.now()}-fallback`);
  const approval = {
    approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    daemonId: '11'.repeat(32),
    agentKeyId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    status: 'pending',
    reason: 'Manual approval required',
    actionType: 'transfer',
    chainId: 999999,
    recipient: '0x3333333333333333333333333333333333333333',
    asset: 'erc20:0x1111111111111111111111111111111111111111',
    amountWei: '123456789',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  assert.equal(display.formatApprovalAmount(approval), '123456789');
  assert.equal(display.formatApprovalAsset(approval), approval.asset);
});
