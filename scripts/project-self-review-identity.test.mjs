import assert from 'node:assert/strict';
import test from 'node:test';

import {
  compareGatewayIdentity,
  identityNeedsWarning,
  isFingerprint,
  usesCurrentProductNavigation
} from './project-self-review-identity.mjs';

const CURRENT_CODE = 'a'.repeat(64);
const CURRENT_SOURCE = 'b'.repeat(64);

test('source/code changes block persisted gateway evidence', () => {
  const identity = compareGatewayIdentity(
    {
      gateway_code_fingerprint: 'c'.repeat(64),
      gateway_source_fingerprint: CURRENT_SOURCE
    },
    { currentCodeFingerprint: CURRENT_CODE, currentSourceFingerprint: CURRENT_SOURCE }
  );

  assert.equal(identity.status, 'code-mismatch');
  assert.equal(identity.current_identity_valid, false);
  assert.equal(identity.context_mismatch, false);
});

test('deployment-only differences are visible context mismatches', () => {
  const identity = compareGatewayIdentity(
    {
      gateway_code_fingerprint: CURRENT_CODE,
      gateway_source_fingerprint: 'd'.repeat(64)
    },
    { currentCodeFingerprint: CURRENT_CODE, currentSourceFingerprint: CURRENT_SOURCE }
  );

  assert.equal(identity.status, 'context-mismatch');
  assert.equal(identity.current_identity_valid, true);
  assert.equal(identity.context_mismatch, true);
  assert.equal(identityNeedsWarning(identity), true);
});

test('matching code and deployment fingerprints are fully current', () => {
  const identity = compareGatewayIdentity(
    {
      gateway_code_fingerprint: CURRENT_CODE,
      gateway_source_fingerprint: CURRENT_SOURCE
    },
    { currentCodeFingerprint: CURRENT_CODE, currentSourceFingerprint: CURRENT_SOURCE }
  );

  assert.equal(identity.status, 'matched');
  assert.equal(identity.current_identity_valid, true);
  assert.equal(identityNeedsWarning(identity), false);
});

test('legacy source-only evidence stays strict', () => {
  const identity = compareGatewayIdentity(
    { gateway_source_fingerprint: 'e'.repeat(64) },
    { currentCodeFingerprint: CURRENT_CODE, currentSourceFingerprint: CURRENT_SOURCE }
  );

  assert.equal(identity.status, 'source-mismatch');
  assert.equal(identity.current_identity_valid, false);
});

test('fingerprint validation rejects malformed values', () => {
  assert.equal(isFingerprint(CURRENT_CODE), true);
  assert.equal(isFingerprint('not-a-fingerprint'), false);
});

test('current product navigation is accepted as the runtime entry contract', () => {
  assert.equal(
    usesCurrentProductNavigation(
      "export const navigation = { defaultPage: ProductPageKey = 'protection', items: [{ key: 'protection' }, { key: 'events' }, { key: 'settings' }] };"
    ),
    true
  );
  assert.equal(usesCurrentProductNavigation("defaultPage: PageKey = 'gateway'"), false);
});
