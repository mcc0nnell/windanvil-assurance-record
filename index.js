// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const VERDICTS = new Set(["PASS", "FAIL", "BLOCKED"]);
const RFC3339_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function normalizedJson(value, stack = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("canonical JSON rejects non-finite numbers");
    }
    return value;
  }

  if (typeof value !== "object") {
    throw new TypeError(`canonical JSON rejects ${typeof value}`);
  }

  if (stack.has(value)) {
    throw new TypeError("canonical JSON rejects circular structures");
  }

  stack.add(value);
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        if (!Object.hasOwn(value, i)) {
          throw new TypeError("canonical JSON rejects sparse arrays");
        }
      }
      return value.map((item) => normalizedJson(item, stack));
    }

    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError("canonical JSON accepts only plain JSON objects");
    }

    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new TypeError("canonical JSON rejects symbol keys");
    }

    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = normalizedJson(value[key], stack);
    }
    return out;
  } finally {
    stack.delete(value);
  }
}

export function canonicalJson(value) {
  return `${JSON.stringify(normalizedJson(value))}\n`;
}

export function digestOf(value) {
  const hex = createHash("sha256").update(canonicalJson(value)).digest("hex");
  return `sha256:${hex}`;
}

export function isDigest(value) {
  return typeof value === "string" && DIGEST.test(value);
}

function requireDigest(label, value) {
  if (!isDigest(value)) {
    throw new TypeError(`${label} must be a canonical sha256:<hex> digest`);
  }
}

function requireNonEmptyString(label, value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${label} must be a non-empty string`);
  }
}

function normalizeDigests(label, values) {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  const normalized = [...new Set(values)];
  for (const value of normalized) requireDigest(label, value);
  return normalized.sort();
}

function requireVerdict(value) {
  if (!VERDICTS.has(value)) {
    throw new TypeError(`verdict must be PASS, FAIL, or BLOCKED`);
  }
}

/**
 * Evaluate an explicit set of required assertions without permitting vacuous PASS.
 *
 * Precedence:
 *   1. Any proven required failure -> FAIL.
 *   2. Otherwise, any missing or BLOCKED required assertion -> BLOCKED.
 *   3. Only a complete set of required PASS assertions -> PASS.
 */
export function evaluateRequiredAssertions(requiredAssertionIds, assertions) {
  if (!Array.isArray(requiredAssertionIds) || !Array.isArray(assertions)) {
    throw new TypeError("requiredAssertionIds and assertions must be arrays");
  }

  if (requiredAssertionIds.length === 0) {
    return { verdict: "BLOCKED", reason: "no required assertions were declared" };
  }

  const required = [];
  const requiredSeen = new Set();
  for (const id of requiredAssertionIds) {
    requireNonEmptyString("required assertion id", id);
    if (requiredSeen.has(id)) throw new TypeError(`duplicate required assertion id: ${id}`);
    requiredSeen.add(id);
    required.push(id);
  }

  const byId = new Map();
  for (const assertion of assertions) {
    if (!assertion || typeof assertion !== "object") {
      throw new TypeError("each assertion must be an object");
    }
    requireNonEmptyString("assertion id", assertion.id);
    requireVerdict(assertion.verdict);
    if (byId.has(assertion.id)) throw new TypeError(`duplicate assertion: ${assertion.id}`);
    byId.set(assertion.id, assertion);
  }

  const failures = required.filter((id) => byId.get(id)?.verdict === "FAIL").sort();
  if (failures.length) {
    return { verdict: "FAIL", reason: `required assertion failed: ${failures.join(", ")}` };
  }

  const missing = required.filter((id) => !byId.has(id)).sort();
  if (missing.length) {
    return { verdict: "BLOCKED", reason: `missing required assertion: ${missing.join(", ")}` };
  }

  const blocked = required.filter((id) => byId.get(id)?.verdict === "BLOCKED").sort();
  if (blocked.length) {
    return { verdict: "BLOCKED", reason: `required assertion blocked: ${blocked.join(", ")}` };
  }

  return { verdict: "PASS", reason: "all required assertions passed" };
}

/**
 * Build WindAnvil Assurance Record v1 from already-decided evidence.
 *
 * This function does not invent or upgrade a verdict. The caller supplies the
 * terminal verdict; this package validates the record shape, normalizes digest
 * sets, and binds the record to a self-digest.
 */
export function buildAssuranceRecord(input) {
  if (!input || typeof input !== "object") throw new TypeError("input must be an object");
  if (!input.subject || typeof input.subject !== "object") {
    throw new TypeError("subject must be an object");
  }
  requireNonEmptyString("subject.kind", input.subject.kind);
  if (!input.subject.identity || typeof input.subject.identity !== "object") {
    throw new TypeError("subject.identity must be an object");
  }

  requireNonEmptyString("policy.id", input.policy?.id);
  requireDigest("policy.digest", input.policy?.digest);
  requireDigest("plan.digest", input.plan?.digest);
  requireDigest("receipt.id", input.receipt?.id);
  requireDigest("receipt.digest", input.receipt?.digest);
  requireVerdict(input.verdict?.value);
  requireNonEmptyString("verdict.reason", input.verdict?.reason);

  const generatedAt =
    input.generatedAt instanceof Date
      ? input.generatedAt.toISOString()
      : input.generatedAt ?? new Date().toISOString();

  if (
    typeof generatedAt !== "string" ||
    !RFC3339_DATE_TIME.test(generatedAt) ||
    Number.isNaN(Date.parse(generatedAt))
  ) {
    throw new TypeError("generatedAt must be an ISO-8601 date-time string or Date");
  }

  const unsigned = {
    schemaVersion: 1,
    kind: "windanvil.assurance-record",
    generatedAt,
    authority: {
      record: "windanvil",
      policy: "windanvil",
      verdict: "windanvil",
      externalInstrumentsAuthoritative: false,
    },
    subject: input.subject,
    policy: {
      id: input.policy.id,
      digest: input.policy.digest,
    },
    plan: {
      digest: input.plan.digest,
    },
    receipt: {
      id: input.receipt.id,
      digest: input.receipt.digest,
    },
    verdict: {
      value: input.verdict.value,
      reason: input.verdict.reason,
    },
    evidence: {
      observationDigests: normalizeDigests(
        "evidence.observationDigests",
        input.evidence?.observationDigests ?? [],
      ),
      artifactDigests: normalizeDigests(
        "evidence.artifactDigests",
        input.evidence?.artifactDigests ?? [],
      ),
    },
    oscal: {
      instrument: "compliance-trestle",
      role: "oscal_validation_instrument",
      targetModel: "assessment-results",
      authoritative: false,
      mode: "validate_and_transform",
    },
  };

  return { ...unsigned, digest: digestOf(unsigned) };
}

export function verifyAssuranceRecordDigest(record) {
  if (!record || typeof record !== "object" || !isDigest(record.digest)) return false;
  const { digest, ...unsigned } = record;
  return digestOf(unsigned) === digest;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const VIVISECTION_JUDGMENT = {
  authority: new Set(["VALID", "INVALID", "NOT_EVALUATED"]),
  binding: new Set(["VALID", "INVALID"]),
  evidence: new Set(["COMPLETE", "INCOMPLETE"]),
  effects: new Set(["CONFORMANT", "VIOLATION", "NOT_APPLICABLE"]),
  causality: new Set(["COMPLETE", "PARTIAL", "BROKEN", "NOT_EVALUATED"]),
  reconstructability: new Set(["YES", "NO", "BLOCKED"]),
  replay: new Set(["MATCH", "DIVERGED", "NOT_RUN", "BLOCKED"]),
};

function requireSha256Hex(label, value) {
  if (typeof value !== "string" || !SHA256_HEX.test(value)) {
    throw new TypeError(`${label} must be a lowercase 64-character SHA-256 hex string`);
  }
}

function requirePositiveSafeInteger(label, value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
}

function normalizeStrings(label, values) {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  const normalized = [...new Set(values)];
  for (const value of normalized) requireNonEmptyString(label, value);
  return normalized.sort();
}

function requireVivisectionJudgment(label, value) {
  if (!VIVISECTION_JUDGMENT[label]?.has(value)) {
    throw new TypeError(`judgment.${label} has invalid value: ${value}`);
  }
}

/**
 * Build a first-class Vivisection Assurance Record.
 *
 * This is intentionally a sibling of the production execution record rather
 * than debug metadata. It binds an experiment to exact Blade authority,
 * artifact identity, probe/effect scope, the one-shot receipt chain, and an
 * independent WindAnvil judgment. The caller supplies the terminal verdict;
 * this package never upgrades experimental success into production correctness.
 */
export function buildVivisectionAssuranceRecord(input) {
  if (!input || typeof input !== "object") throw new TypeError("input must be an object");

  requireNonEmptyString("identity.experimentId", input.identity?.experimentId);
  requireNonEmptyString("identity.sessionId", input.identity?.sessionId);
  requireNonEmptyString("identity.causalId", input.identity?.causalId);

  requireNonEmptyString("subject.manifestId", input.subject?.manifestId);
  requireNonEmptyString("subject.capability", input.subject?.capability);
  if (!Number.isInteger(input.subject?.bundleId) || input.subject.bundleId < 0) {
    throw new TypeError("subject.bundleId must be a non-negative integer");
  }
  requireSha256Hex("subject.bundleSha256", input.subject.bundleSha256);

  requireNonEmptyString("authority.capabilityManifest.id", input.authority?.capabilityManifest?.id);
  requireDigest("authority.capabilityManifest.digest", input.authority?.capabilityManifest?.digest);
  if (input.authority.capabilityManifest.id !== input.subject.manifestId) {
    throw new TypeError("capability manifest authority does not match the subject manifest");
  }

  const grant = input.authority?.vivisectionGrant;
  requireNonEmptyString("authority.vivisectionGrant.id", grant?.id);
  requireDigest("authority.vivisectionGrant.digest", grant?.digest);
  requireNonEmptyString("authority.vivisectionGrant.bladeId", grant?.bladeId);
  requireNonEmptyString("authority.vivisectionGrant.keyId", grant?.keyId);
  requirePositiveSafeInteger("authority.vivisectionGrant.authorizationEpoch", grant?.authorizationEpoch);
  requirePositiveSafeInteger("authority.vivisectionGrant.notAfterUnix", grant?.notAfterUnix);
  const allowedEffects = normalizeStrings(
    "authority.vivisectionGrant.allowedEffects",
    grant?.allowedEffects ?? [],
  );

  requireNonEmptyString("experiment.probeName", input.experiment?.probeName);
  requireNonEmptyString("experiment.probeVersion", input.experiment?.probeVersion);
  requireSha256Hex("experiment.probeDescriptorSha256", input.experiment?.probeDescriptorSha256);
  requireSha256Hex("experiment.inputSha256", input.experiment?.inputSha256);
  requireSha256Hex("experiment.requestSha256", input.experiment?.requestSha256);
  requireSha256Hex("experiment.authorizationIdSha256", input.experiment?.authorizationIdSha256);
  if (input.experiment?.outputSha256 !== undefined) {
    requireSha256Hex("experiment.outputSha256", input.experiment.outputSha256);
  }
  if (input.experiment?.terminal !== "COMPLETED" && input.experiment?.terminal !== "FAILED") {
    throw new TypeError("experiment.terminal must be COMPLETED or FAILED");
  }
  if (input.experiment.terminal === "COMPLETED" && input.experiment.outputSha256 === undefined) {
    throw new TypeError("completed experiment must bind outputSha256");
  }
  if (input.experiment.terminal === "FAILED" && input.experiment.outputSha256 !== undefined) {
    throw new TypeError("failed experiment must not claim outputSha256");
  }

  const requestedEffects = normalizeStrings(
    "experiment.requestedEffects",
    input.experiment?.requestedEffects ?? [],
  );
  const exercisedEffects = normalizeStrings(
    "experiment.exercisedEffects",
    input.experiment?.exercisedEffects ?? [],
  );

  for (const effect of requestedEffects) {
    if (!allowedEffects.includes(effect)) {
      throw new TypeError(`requested effect is outside signed authority: ${effect}`);
    }
  }
  for (const effect of exercisedEffects) {
    if (!requestedEffects.includes(effect)) {
      throw new TypeError(`exercised effect was not requested: ${effect}`);
    }
  }

  const receiptNames = [
    "opened",
    "grantVerified",
    "grantAdmitted",
    "grantBound",
    "grantAuthorized",
    "probeAuthorized",
    "authorizationConsumed",
    "terminal",
    "closed",
  ];
  for (const name of receiptNames) {
    requireDigest(`receipts.${name}`, input.receipts?.[name]);
  }

  for (const label of Object.keys(VIVISECTION_JUDGMENT)) {
    requireVivisectionJudgment(label, input.judgment?.[label]);
  }

  requireVerdict(input.verdict?.value);
  requireNonEmptyString("verdict.reason", input.verdict?.reason);

  const generatedAt =
    input.generatedAt instanceof Date
      ? input.generatedAt.toISOString()
      : input.generatedAt ?? new Date().toISOString();
  if (
    typeof generatedAt !== "string" ||
    !RFC3339_DATE_TIME.test(generatedAt) ||
    Number.isNaN(Date.parse(generatedAt))
  ) {
    throw new TypeError("generatedAt must be an ISO-8601 date-time string or Date");
  }

  const unsigned = {
    schemaVersion: 1,
    kind: "windanvil.vivisection-assurance-record",
    generatedAt,
    identity: {
      experimentId: input.identity.experimentId,
      sessionId: input.identity.sessionId,
      causalId: input.identity.causalId,
    },
    subject: {
      manifestId: input.subject.manifestId,
      capability: input.subject.capability,
      bundleId: input.subject.bundleId,
      bundleSha256: input.subject.bundleSha256,
    },
    authority: {
      capabilityManifest: {
        id: input.authority.capabilityManifest.id,
        digest: input.authority.capabilityManifest.digest,
      },
      vivisectionGrant: {
        id: grant.id,
        digest: grant.digest,
        bladeId: grant.bladeId,
        keyId: grant.keyId,
        authorizationEpoch: grant.authorizationEpoch,
        notAfterUnix: grant.notAfterUnix,
        allowedEffects,
      },
    },
    experiment: {
      probeName: input.experiment.probeName,
      probeVersion: input.experiment.probeVersion,
      probeDescriptorSha256: input.experiment.probeDescriptorSha256,
      inputSha256: input.experiment.inputSha256,
      requestSha256: input.experiment.requestSha256,
      authorizationIdSha256: input.experiment.authorizationIdSha256,
      ...(input.experiment.outputSha256 !== undefined
        ? { outputSha256: input.experiment.outputSha256 }
        : {}),
      terminal: input.experiment.terminal,
      requestedEffects,
      exercisedEffects,
    },
    receipts: {
      opened: input.receipts.opened,
      grantVerified: input.receipts.grantVerified,
      grantAdmitted: input.receipts.grantAdmitted,
      grantBound: input.receipts.grantBound,
      grantAuthorized: input.receipts.grantAuthorized,
      probeAuthorized: input.receipts.probeAuthorized,
      authorizationConsumed: input.receipts.authorizationConsumed,
      terminal: input.receipts.terminal,
      closed: input.receipts.closed,
    },
    judgment: {
      authority: input.judgment.authority,
      binding: input.judgment.binding,
      evidence: input.judgment.evidence,
      effects: input.judgment.effects,
      causality: input.judgment.causality,
      reconstructability: input.judgment.reconstructability,
      replay: input.judgment.replay,
    },
    verdict: {
      value: input.verdict.value,
      reason: input.verdict.reason,
    },
    evidence: {
      observationDigests: normalizeDigests(
        "evidence.observationDigests",
        input.evidence?.observationDigests ?? [],
      ),
      artifactDigests: normalizeDigests(
        "evidence.artifactDigests",
        input.evidence?.artifactDigests ?? [],
      ),
    },
  };

  return { ...unsigned, digest: digestOf(unsigned) };
}
