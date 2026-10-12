// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildAssuranceRecord,
  canonicalJson,
  digestOf,
  evaluateRequiredAssertions,
  verifyAssuranceRecordDigest,
} from "../index.js";

test("canonical JSON is stable across object-key order", () => {
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
});

test("canonical JSON rejects non-JSON and ambiguous values", () => {
  assert.throws(() => canonicalJson({ value: undefined }), /rejects undefined/);
  assert.throws(() => canonicalJson({ value: Number.NaN }), /non-finite/);
  assert.throws(() => canonicalJson(new Date()), /plain JSON objects/);

  const sparse = [];
  sparse[1] = "x";
  assert.throws(() => canonicalJson(sparse), /sparse arrays/);

  const circular = {};
  circular.self = circular;
  assert.throws(() => canonicalJson(circular), /circular/);
});

test("required assertions fail closed instead of producing vacuous PASS", () => {
  assert.deepEqual(evaluateRequiredAssertions([], []), {
    verdict: "BLOCKED",
    reason: "no required assertions were declared",
  });

  assert.equal(
    evaluateRequiredAssertions(["build", "sbom"], [{ id: "build", verdict: "PASS" }]).verdict,
    "BLOCKED",
  );

  assert.equal(
    evaluateRequiredAssertions(
      ["build", "sbom"],
      [
        { id: "build", verdict: "PASS" },
        { id: "sbom", verdict: "FAIL" },
      ],
    ).verdict,
    "FAIL",
  );

  assert.equal(
    evaluateRequiredAssertions(
      ["build", "sbom"],
      [
        { id: "build", verdict: "PASS" },
        { id: "sbom", verdict: "PASS" },
      ],
    ).verdict,
    "PASS",
  );
});

test("assurance record is self-digesting and tamper-evident", () => {
  const record = buildAssuranceRecord({
    generatedAt: "2026-09-06T22:00:00.000Z",
    subject: {
      kind: "immutable_git_object",
      identity: { provider: "example", sha: "0123456789abcdef" },
    },
    policy: { id: "example.policy.v1", digest: digestOf("policy") },
    plan: { digest: digestOf("plan") },
    receipt: { id: digestOf("receipt-id"), digest: digestOf("receipt") },
    verdict: { value: "PASS", reason: "all required assertions passed" },
    evidence: {
      observationDigests: [digestOf("observation-b"), digestOf("observation-a")],
      artifactDigests: [digestOf("artifact")],
    },
  });

  assert.equal(record.kind, "windanvil.assurance-record");
  assert.deepEqual(
    record.evidence.observationDigests,
    [...record.evidence.observationDigests].sort(),
  );
  assert.equal(verifyAssuranceRecordDigest(record), true);

  const tampered = { ...record, verdict: { ...record.verdict, value: "FAIL" } };
  assert.equal(verifyAssuranceRecordDigest(tampered), false);
});

test("malformed digests are rejected", () => {
  assert.throws(
    () =>
      buildAssuranceRecord({
        subject: { kind: "artifact", identity: { id: "x" } },
        policy: { id: "p", digest: "not-a-digest" },
        plan: { digest: digestOf("plan") },
        receipt: { id: digestOf("id"), digest: digestOf("receipt") },
        verdict: { value: "BLOCKED", reason: "missing proof" },
      }),
    /policy\.digest/,
  );
});

test("canonical JSON preserves own __proto__ keys as signed data", () => {
  const first = JSON.parse('{"x":1,"__proto__":{"marker":"A"}}');
  const second = JSON.parse('{"x":1,"__proto__":{"marker":"B"}}');
  assert.match(canonicalJson(first), /"__proto__":\{"marker":"A"\}/);
  assert.notEqual(canonicalJson(first), canonicalJson(second));
  assert.notEqual(digestOf(first), digestOf(second));
  assert.deepEqual(Object.getPrototypeOf(first), Object.prototype);
});

test("nested prototype-named properties remain evidence-bound without prototype pollution", () => {
  const a = JSON.parse('{"outer":{"__proto__":{"tag":"one"},"constructor":"data"}}');
  const b = JSON.parse('{"outer":{"__proto__":{"tag":"two"},"constructor":"data"}}');
  assert.notEqual(digestOf(a), digestOf(b));
  assert.equal(JSON.parse(canonicalJson(a)).outer.__proto__.tag, "one");
  assert.equal(({}).tag, undefined);
  assert.equal(digestOf({ a: 1, b: 2 }), digestOf({ b: 2, a: 1 }));
});
