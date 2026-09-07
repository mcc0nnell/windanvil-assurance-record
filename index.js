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
