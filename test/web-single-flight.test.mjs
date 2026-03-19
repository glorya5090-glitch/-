import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/src/lib/single-flight.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('single-flight gate rejects re-entry until released', async () => {
  const { createSingleFlightGate } = await loadModule('gate');
  const gate = createSingleFlightGate();

  assert.equal(gate.locked, false);
  assert.equal(gate.enter(), true);
  assert.equal(gate.locked, true);
  assert.equal(gate.enter(), false);

  gate.release();

  assert.equal(gate.locked, false);
  assert.equal(gate.enter(), true);
});

test('single-flight gates are independent per action', async () => {
  const { createSingleFlightGate } = await loadModule('independent');
  const submitGate = createSingleFlightGate();
  const recoveryGate = createSingleFlightGate();

  assert.equal(submitGate.enter(), true);
  assert.equal(recoveryGate.enter(), true);
  assert.equal(submitGate.enter(), false);
  assert.equal(recoveryGate.enter(), false);

  submitGate.release();

  assert.equal(submitGate.enter(), true);
  assert.equal(recoveryGate.locked, true);
});
