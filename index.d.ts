// SPDX-License-Identifier: Apache-2.0

export type Verdict = "PASS" | "FAIL" | "BLOCKED";

export interface Assertion {
  id: string;
  verdict: Verdict;
  reason?: string;
}

export interface AssertionEvaluation {
  verdict: Verdict;
  reason: string;
}

export interface AssuranceSubject {
  kind: string;
  identity: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AssuranceRecord {
  schemaVersion: 1;
  kind: "windanvil.assurance-record";
  generatedAt: string;
  authority: {
    record: "windanvil";
    policy: "windanvil";
    verdict: "windanvil";
    externalInstrumentsAuthoritative: false;
  };
  subject: AssuranceSubject;
  policy: { id: string; digest: string };
  plan: { digest: string };
  receipt: { id: string; digest: string };
  verdict: { value: Verdict; reason: string };
  evidence: {
    observationDigests: string[];
    artifactDigests: string[];
  };
  oscal: {
    instrument: "compliance-trestle";
    role: "oscal_validation_instrument";
    targetModel: "assessment-results";
    authoritative: false;
    mode: "validate_and_transform";
  };
  digest: string;
}

export interface AssuranceRecordInput {
  generatedAt?: string | Date;
  subject: AssuranceSubject;
  policy: { id: string; digest: string };
  plan: { digest: string };
  receipt: { id: string; digest: string };
  verdict: { value: Verdict; reason: string };
  evidence?: {
    observationDigests?: string[];
    artifactDigests?: string[];
  };
}

export type VivisectionAuthorityJudgment = "VALID" | "INVALID" | "NOT_EVALUATED";
export type VivisectionBindingJudgment = "VALID" | "INVALID";
export type VivisectionEvidenceJudgment = "COMPLETE" | "INCOMPLETE";
export type VivisectionEffectsJudgment = "CONFORMANT" | "VIOLATION" | "NOT_APPLICABLE";
export type VivisectionCausalityJudgment = "COMPLETE" | "PARTIAL" | "BROKEN" | "NOT_EVALUATED";
export type VivisectionReconstructabilityJudgment = "YES" | "NO" | "BLOCKED";
export type VivisectionReplayJudgment = "MATCH" | "DIVERGED" | "NOT_RUN" | "BLOCKED";

export interface VivisectionAssuranceRecord {
  schemaVersion: 1;
  kind: "windanvil.vivisection-assurance-record";
  generatedAt: string;
  identity: {
    experimentId: string;
    sessionId: string;
    causalId: string;
  };
  subject: {
    manifestId: string;
    capability: string;
    bundleId: number;
    bundleSha256: string;
  };
  authority: {
    capabilityManifest: {
      id: string;
      digest: string;
    };
    vivisectionGrant: {
      id: string;
      digest: string;
      bladeId: string;
      keyId: string;
      authorizationEpoch: number;
      notAfterUnix: number;
      allowedEffects: string[];
    };
  };
  experiment: {
    probeName: string;
    probeDescriptorSha256: string;
    inputSha256: string;
    outputSha256?: string;
    requestedEffects: string[];
    exercisedEffects: string[];
  };
  receipts: {
    opened: string;
    grantVerified: string;
    grantAdmitted: string;
    grantBound: string;
    grantAuthorized: string;
    probeAuthorized: string;
    authorizationConsumed: string;
    terminal: string;
    closed: string;
  };
  judgment: {
    authority: VivisectionAuthorityJudgment;
    binding: VivisectionBindingJudgment;
    evidence: VivisectionEvidenceJudgment;
    effects: VivisectionEffectsJudgment;
    causality: VivisectionCausalityJudgment;
    reconstructability: VivisectionReconstructabilityJudgment;
    replay: VivisectionReplayJudgment;
  };
  verdict: { value: Verdict; reason: string };
  evidence: {
    observationDigests: string[];
    artifactDigests: string[];
  };
  digest: string;
}

export interface VivisectionAssuranceRecordInput {
  generatedAt?: string | Date;
  identity: VivisectionAssuranceRecord["identity"];
  subject: VivisectionAssuranceRecord["subject"];
  authority: VivisectionAssuranceRecord["authority"];
  experiment: VivisectionAssuranceRecord["experiment"];
  receipts: VivisectionAssuranceRecord["receipts"];
  judgment: VivisectionAssuranceRecord["judgment"];
  verdict: VivisectionAssuranceRecord["verdict"];
  evidence?: {
    observationDigests?: string[];
    artifactDigests?: string[];
  };
}

export function canonicalJson(value: unknown): string;
export function digestOf(value: unknown): string;
export function isDigest(value: unknown): value is string;
export function evaluateRequiredAssertions(
  requiredAssertionIds: string[],
  assertions: Assertion[],
): AssertionEvaluation;
export function buildAssuranceRecord(input: AssuranceRecordInput): AssuranceRecord;
export function buildVivisectionAssuranceRecord(
  input: VivisectionAssuranceRecordInput,
): VivisectionAssuranceRecord;
export function verifyAssuranceRecordDigest(
  record: AssuranceRecord | VivisectionAssuranceRecord | unknown,
): boolean;
