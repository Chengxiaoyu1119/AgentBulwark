const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/i;

export function isFingerprint(value) {
  return typeof value === 'string' && FINGERPRINT_PATTERN.test(value);
}

/**
 * Compare persisted gateway evidence with the process that is reviewing it.
 *
 * The code fingerprint is the immutable source/contract identity.  The source
 * fingerprint also includes deployment configuration, provider routing and
 * MCP/runtime values, so it can legitimately differ between a fixed evidence
 * process and an independent shell.  A code match therefore keeps the
 * evidence bound to the reviewed implementation while a deployment mismatch
 * remains visible as context rather than being reported as stale source.
 */
export function compareGatewayIdentity(
  artifact,
  { currentCodeFingerprint = '', currentSourceFingerprint = '' } = {}
) {
  const payload = artifact && typeof artifact === 'object' ? artifact : {};
  const artifactCodeFingerprint = typeof payload.gateway_code_fingerprint === 'string'
    ? payload.gateway_code_fingerprint
    : '';
  const artifactSourceFingerprint = typeof payload.gateway_source_fingerprint === 'string'
    ? payload.gateway_source_fingerprint
    : '';
  const codePresent = Boolean(artifactCodeFingerprint);
  const sourcePresent = Boolean(artifactSourceFingerprint);
  const codeFormatValid = !codePresent || isFingerprint(artifactCodeFingerprint);
  const sourceFormatValid = !sourcePresent || isFingerprint(artifactSourceFingerprint);
  const currentCodeAvailable = isFingerprint(currentCodeFingerprint);
  const currentSourceAvailable = isFingerprint(currentSourceFingerprint);
  const codeMatchesCurrent = codePresent && codeFormatValid && currentCodeAvailable
    ? artifactCodeFingerprint === currentCodeFingerprint
    : false;
  const sourceMatchesCurrent = sourcePresent && sourceFormatValid && currentSourceAvailable
    ? artifactSourceFingerprint === currentSourceFingerprint
    : false;

  let status = 'missing';
  let currentIdentityValid = false;
  if (codePresent) {
    if (!codeFormatValid) {
      status = 'invalid-code-fingerprint';
    } else if (!currentCodeAvailable) {
      status = 'current-code-unavailable';
    } else if (!codeMatchesCurrent) {
      status = 'code-mismatch';
    } else {
      currentIdentityValid = true;
      if (!sourcePresent || !sourceFormatValid || !currentSourceAvailable) {
        status = 'context-unavailable';
      } else if (!sourceMatchesCurrent) {
        status = 'context-mismatch';
      } else {
        status = 'matched';
      }
    }
  } else if (sourcePresent) {
    // Older evidence may not carry the split code fingerprint.  Keep that
    // compatibility path strict against the complete deployment fingerprint.
    if (!sourceFormatValid) {
      status = 'invalid-source-fingerprint';
    } else if (!currentSourceAvailable) {
      status = 'current-source-unavailable';
    } else if (sourceMatchesCurrent) {
      currentIdentityValid = true;
      status = 'legacy-source-only';
    } else {
      status = 'source-mismatch';
    }
  }

  return {
    artifact_code_fingerprint: artifactCodeFingerprint,
    artifact_source_fingerprint: artifactSourceFingerprint,
    code_fingerprint_present: codePresent,
    source_fingerprint_present: sourcePresent,
    code_fingerprint_matches_current: codeMatchesCurrent,
    source_fingerprint_matches_current: sourceMatchesCurrent,
    current_identity_valid: currentIdentityValid,
    context_mismatch: status === 'context-mismatch',
    status
  };
}

export function identityNeedsWarning(identity) {
  return ['context-mismatch', 'context-unavailable', 'legacy-source-only'].includes(identity?.status);
}

export function identityNote(identity, label = '网关证据') {
  switch (identity?.status) {
    case 'matched':
      return `${label}代码指纹与当前源码一致，部署 source/config 指纹一致。`;
    case 'context-mismatch':
      return `${label}代码指纹与当前源码一致，但部署 source/config 指纹不同；记录为 context mismatch。`;
    case 'context-unavailable':
      return `${label}代码指纹与当前源码一致，但部署 source/config 指纹不可完整比较；记录为 context mismatch。`;
    case 'legacy-source-only':
      return `${label}仅携带旧版部署 source/config 指纹且匹配当前环境；代码指纹缺失，按兼容路径记录。`;
    case 'invalid-code-fingerprint':
      return `${label}代码指纹格式无效，当前实现身份未通过。`;
    case 'current-code-unavailable':
      return `当前代码指纹不可计算，${label}身份未通过。`;
    case 'code-mismatch':
      return `${label}代码指纹与当前源码不一致，证据按源码过期处理。`;
    case 'invalid-source-fingerprint':
      return `${label}部署 source/config 指纹格式无效，身份未通过。`;
    case 'current-source-unavailable':
      return `当前部署 source/config 指纹不可计算，${label}身份未通过。`;
    case 'source-mismatch':
      return `${label}缺少代码指纹且部署 source/config 指纹不一致，证据身份未通过。`;
    default:
      return `${label}缺少可验证的代码或部署 source/config 指纹。`;
  }
}
