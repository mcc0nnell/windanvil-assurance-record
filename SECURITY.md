# Security policy

WindAnvil Assurance Record is security-sensitive infrastructure. Please do not
open a public issue for a vulnerability that could enable forged, downgraded,
or misleading assurance results.

Report suspected vulnerabilities privately to **robert@mcc0nnell.org** with:

- the affected version or commit;
- the security invariant you believe can be bypassed;
- a minimal reproduction when practical; and
- whether exploitation could turn missing or failed proof into `PASS`, alter a
  bound digest without detection, or confuse record identity/provenance.

Please avoid including real customer evidence, secrets, credentials, or
non-public source material in a report.

## Security model

The package is designed to fail closed around explicit required assertions:

- a proven required failure is `FAIL`;
- missing or blocked required proof is `BLOCKED`; and
- `PASS` requires every declared required assertion to be present and passing.

The package's self-digest is tamper-evidence, not a digital signature or an
identity credential. Consumers that require origin authentication must add an
appropriate signing/attestation layer and verify it independently.
