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

export function canonicalJson(value: unknown): string;
export function digestOf(value: unknown): string;
export function isDigest(value: unknown): value is string;
export function evaluateRequiredAssertions(
  requiredAssertionIds: string[],
  assertions: Assertion[],
): AssertionEvaluation;
export function buildAssuranceRecord(input: AssuranceRecordInput): AssuranceRecord;
export function verifyAssuranceRecordDigest(record: AssuranceRecord | unknown): boolean;
