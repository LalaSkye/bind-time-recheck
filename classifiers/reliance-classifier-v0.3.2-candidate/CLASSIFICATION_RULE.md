# Classification Rule - Reliance After Change (local candidate v0.3.2)

Synthetic specimen only. Not evidence of operational performance in a deployed system.

R1 binding checks and R2 conflict handling are unchanged. This candidate finishes R3 on both routes that can return CLAIM_CONTRADICTED.

## Field paths (R1, unchanged)

Ticket: configuration.ticket and configuration.issuer_seed_request.ticket.
Bound instruction: configuration.driver_supplied_packet_sha256, configuration.issuer_seed_request.packet_sha256, observed.check_packet_sha256_observed, observed.bind_packet_sha256_observed.

## Execution eligibility

Taken from observed.bind_reason. Eligibility is final permission to enter the writer. Writer entry is a witness of crossing. Write completion is a later observation. Zero writer entries alone do not mean refusal.

## Observation consistency (R2, unchanged)

written with writer_entry_count=0 is UNRESOLVED. A recorded refusal with writer entry is UNRESOLVED.

## Withdrawal timing (R3, both paths)

Every withdrawal-based CLAIM_CONTRADICTED requires source-grounded evidence that effective withdrawal for the same ticket and bound instruction preceded the eligibility decision. This does not depend on trust_prior_used.

The order check is anchored to issuer_revocation_acknowledged whose revoked value equals configuration.ticket. It must precede the single writer_entered. An acknowledgement for another ticket does not satisfy that requirement.

Both routes pass through that check:

- Cached path: trust_prior_used continuing effect. The matching acknowledgement must still precede writer_entered.
- Fresh path: a later refusing live_read. A refusing read after write_completed cannot, by itself, establish invalid authorisation at the earlier decision. The matching acknowledgement must still precede writer_entered.

A genuine refusal such as A does not need a writer-entry witness. A genuine no-withdrawal reference such as B does not need a withdrawal event.

Missing, malformed, conflicting or ambiguous ordering evidence needed for a contradiction returns UNRESOLVED with a specific reason. An altered trace outside the pinned single-invocation sequence is not treated as a valid original run.

## Application to the preserved receipt

- Case M: acknowledgement precedes writer_entered, trust_prior used. CLAIM_CONTRADICTED.
- Case A: refusal after acknowledgement, no writer entry. NOT_CONTRADICTED_BY_THIS_OBSERVATION.
- Case B: no withdrawal. NOT_CONTRADICTED_BY_THIS_OBSERVATION.

BASIS_REQUIRES_REVALIDATION and BENIGN_CHANGE remain unexercised.
