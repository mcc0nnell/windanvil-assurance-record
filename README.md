# WindAnvil Assurance Record

A small, dependency-free open-source package for portable software-assurance records.

It provides three things:

1. deterministic SHA-256 digests over WindAnvil canonical JSON,
2. a fail-closed evaluator for explicitly required assertions, and
3. WindAnvil Assurance Record v1 construction and self-digest verification.

The package is intentionally narrower than the WindAnvil service. It does **not**
run builds, choose policy, scan source code, store private evidence, or turn a
missing check into PASS.

## Fail-closed rule

`PASS` requires a complete set of required assertions whose verdicts are all
`PASS`.

A proven required failure returns `FAIL`. A missing or blocked required
assertion returns `BLOCKED`.

```js
import { evaluateRequiredAssertions } from "windanvil-assurance-record";

const result = evaluateRequiredAssertions(
  ["build", "sbom"],
  [{ id: "build", verdict: "PASS" }],
);

console.log(result);
// { verdict: "BLOCKED", reason: "missing required assertion: sbom" }
```

## Assurance Record

```js
import {
  buildAssuranceRecord,
  digestOf,
  verifyAssuranceRecordDigest,
} from "windanvil-assurance-record";

const record = buildAssuranceRecord({
  subject: {
    kind: "immutable_git_object",
    identity: { provider: "example", sha: "0123456789abcdef" },
  },
  policy: { id: "example.policy.v1", digest: digestOf("policy") },
  plan: { digest: digestOf("plan") },
  receipt: { id: digestOf("receipt-id"), digest: digestOf("receipt") },
  verdict: { value: "BLOCKED", reason: "required architecture proof unavailable" },
  evidence: { observationDigests: [], artifactDigests: [] },
});

console.log(verifyAssuranceRecordDigest(record)); // true
```

The JSON Schema is exported at `windanvil-assurance-record/schema`.

## Canonical digest input

`digestOf()` accepts JSON-safe primitives, arrays, and plain objects. Object keys
are sorted recursively before hashing. Inputs that JSON could otherwise coerce
or erase are rejected instead of being silently normalized: `undefined`,
functions, symbols, bigints, non-finite numbers, sparse arrays, circular
structures, and non-plain objects such as `Date` instances.

That restriction is deliberate. Evidence digests should not depend on lossy
JavaScript serialization behavior.

## Security invariants

- digests use the canonical `sha256:<64 lowercase hex>` form;
- digest input rejects ambiguous or lossy non-JSON values;
- digest arrays are deduplicated and sorted before the record is sealed;
- no required assertions means `BLOCKED`, never vacuous `PASS`;
- a missing required assertion means `BLOCKED`;
- a proven required failure means `FAIL`;
- the record self-digest detects later mutation;
- the OSCAL bridge remains explicitly non-authoritative.

The package binds evidence. It does not claim that a producer is trustworthy
merely because it can create a syntactically valid record.

## Development

```sh
npm test
npm run pack:check
```

Node.js 20 or later is required. The package has no runtime dependencies.

## License

Apache License 2.0 (`Apache-2.0`), an OSI-approved open-source license.

Only this package distribution is licensed under Apache-2.0. Code outside the
package directory in the private WindAnvil development repository is not
relicensed by this package.
