import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionEpoch, isUnauthorized } from '../src/app/session-epoch.ts';

test('session begins only after the server confirms authentication', () => {
  const state = new SessionEpoch();
  const before = state.snapshot();
  assert.equal(state.isCurrent(before), false);
  const epoch = state.start();
  assert.equal(state.isCurrent(epoch), true);
  assert.equal(state.isCurrent(before), false);
});

test('logout invalidates in-flight device and Browser results', async () => {
  const state = new SessionEpoch();
  const oldEpoch = state.start();
  let resolveRequest;
  const inFlight = new Promise(resolve => { resolveRequest = resolve; });
  state.end();
  resolveRequest({ devices: [{ id: 'previous-user-device' }] });
  const response = await inFlight;
  const visibleDevices = state.isCurrent(oldEpoch) ? response.devices : [];
  assert.deepEqual(visibleDevices, []);
});

test('a new account session cannot accept responses from the previous account', () => {
  const state = new SessionEpoch();
  const previousAccount = state.start();
  state.end();
  const newAccount = state.start();
  assert.equal(state.isCurrent(previousAccount), false);
  assert.equal(state.isCurrent(newAccount), true);
});

test('401 invalidation rejects delayed refresh even without a new login', () => {
  const state = new SessionEpoch();
  const snapshot = state.start();
  assert.equal(isUnauthorized({ status: 401 }), true);
  state.end();
  assert.equal(state.isCurrent(snapshot), false);
});

test('temporary network and server failures do not impersonate an expired session', () => {
  assert.equal(isUnauthorized({ status: 503 }), false);
  assert.equal(isUnauthorized(new Error('network offline')), false);
  assert.equal(isUnauthorized({ status: '401' }), false);
  assert.equal(isUnauthorized(null), false);
});

test('delayed audit and device metadata cannot reappear after account switch', async () => {
  const state = new SessionEpoch();
  const first = state.start();
  let resolveAudit;
  const pendingAudit = new Promise(resolve => { resolveAudit = resolve; });
  state.end();
  const second = state.start();
  resolveAudit({ events: [{ subject: 'previous-account' }] });
  const result = await pendingAudit;
  const nextAudit = state.isCurrent(first) ? result.events : [];
  assert.deepEqual(nextAudit, []);
  assert.equal(state.isCurrent(second), true);
});
