// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildVivisectionAssuranceRecord,
  digestOf,
  verifyAssuranceRecordDigest,
} from "../index.js";

const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);
const HEX_C = "c".repeat(64);

function fixture(overrides = {}) {
  return {
    generatedAt: "2026-09-07T21:30:00.000Z",
    identity: {
      experimentId: "exp-001",
      sessionId: "session-001",
      causalId: "cause-001",
    },
    subject: {
      manifestId: "manifest-001",
      capability: "echo",
      bundleId: 7,
      bundleSha256: HEX_A,
    },
    authority: {
      capabilityManifest: {
        id: "manifest-001",
        digest: digestOf("capability-manifest"),
      },
      vivisectionGrant: {
        id: "viv-grant-001",
        digest: digestOf("vivisection-grant"),
        bladeId: "blade-001",
        keyId: "key-001",
        authorizationEpoch: 1,
        notAfterUnix: 2_000_000_000,
        allowedEffects: ["observe.state"],
      },
    },
    experiment: {
      probeName: "state.snapshot",
      probeDescriptorSha256: HEX_B,
      inputSha256: HEX_C,
      outputSha256: HEX_A,
      requestedEffects: ["observe.state"],
      exercisedEffects: ["observe.state"],
    },
    receipts: {
      opened: digestOf("opened"),
      grantVerified: digestOf("grant-verified"),
      grantAdmitted: digestOf("grant-admitted"),
      grantBound: digestOf("grant-bound"),
      grantAuthorized: digestOf("grant-authorized"),
      probeAuthorized: digestOf("probe-authorized"),
      authorizationConsumed: digestOf("authorization-consumed"),
      terminal: digestOf("terminal"),
      closed: digestOf("closed"),
    },
    judgment: {
      authority: "VALID",
      binding: "VALID",
      evidence: "COMPLETE",
      effects: "CONFORMANT",
      causality: "COMPLETE",
      reconstructability: "YES",
      replay: "NOT_RUN",
    },
    verdict: {
      value: "PASS",
      reason: "experiment authority and evidence are complete",
    },
    evidence: {
      observationDigests: [digestOf("obs-b"), digestOf("obs-a")],
      artifactDigests: [digestOf("artifact")],
    },
    ...overrides,
  };
}

test("Vivisection is a distinct self-digesting assurance record", () => {
  const record = buildVivisectionAssuranceRecord(fixture());

  assert.equal(record.kind, "windanvil.vivisection-assurance-record");
  assert.equal(record.identity.experimentId, "exp-001");
  assert.equal(record.subject.bundleId, 7);
  assert.equal(record.judgment.authority, "VALID");
  assert.equal(record.authority.capabilityManifest.id, record.subject.manifestId);
  assert.equal(verifyAssuranceRecordDigest(record), true);
  assert.deepEqual(record.authority.vivisectionGrant.allowedEffects, ["observe.state"]);
  assert.deepEqual(
    record.evidence.observationDigests,
    [...record.evidence.observationDigests].sort(),
  );
});

test("experimental success cannot silently widen signed effects", () => {
  const input = fixture();
  input.experiment.requestedEffects = ["inject.input"];
  input.experiment.exercisedEffects = ["inject.input"];

  assert.throws(
    () => buildVivisectionAssuranceRecord(input),
    /requested effect is outside signed authority: inject\.input/,
  );
});

test("an exercised effect must have been explicitly requested", () => {
  const input = fixture();
  input.authority.vivisectionGrant.allowedEffects = ["observe.state", "alter.timing"];
  input.experiment.exercisedEffects = ["alter.timing"];

  assert.throws(
    () => buildVivisectionAssuranceRecord(input),
    /exercised effect was not requested: alter\.timing/,
  );
});

test("capability manifest authority must bind the exact subject manifest", () => {
  const input = fixture();
  input.authority.capabilityManifest.id = "other-manifest";

  assert.throws(
    () => buildVivisectionAssuranceRecord(input),
    /capability manifest authority does not match the subject manifest/,
  );
});

test("Vivisection record tampering breaks the self-digest", () => {
  const record = buildVivisectionAssuranceRecord(fixture());
  const tampered = {
    ...record,
    judgment: { ...record.judgment, effects: "VIOLATION" },
  };
  assert.equal(verifyAssuranceRecordDigest(tampered), false);
});
