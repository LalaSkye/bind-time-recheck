# bind-time-recheck — first build, local fixture

Working copy of the 2026-09-26 fixture. Not a GitHub repository. The historical zip and its receipt are not this result.

## Run

Python 3, standard library only. From this directory:

    python3 run.py

The command writes `receipt.json` in this directory and prints the same JSON. Test targets are isolated in a temporary directory and removed after the run.

## Frozen cases

A and B call normal `bind` with `trust_prior` unused. M calls the same `bind` with `trust_prior` set to the initial authority result. That argument is test instrumentation, not a supported feature.

1. Case A, protection. Initial issuer read passes. Withdrawal is acknowledged. Bind digests its own packet argument and performs a fresh issuer read. Expected: `authority_not_current`, writer entry 0, target unchanged.
2. Case B, protection. Same packet, seed, path, payload, ticket, and an equivalently seeded fresh issuer. No withdrawal. Bind performs a fresh issuer read. Expected: writer entry 1, exact payload written.
3. Case M, sensitivity. Same start as A, including acknowledged withdrawal. Bind reuses the earlier pass and does not read the issuer again. Expected: writer entry 1 and payload written. Verdict `SUBSTITUTION_VISIBLE`. This is not protection evidence. If M does not reach the writer, the run fails.

## Observations

`check` computes SHA-256 from its `packet_bytes` argument and returns that digest with the issuer result. `bind` computes SHA-256 from its own `packet_bytes` argument. The driver-supplied digest is configuration. A later rehash of the driver constant is not stored as an observation. Writer entry is counted inside the writer callback before `write_bytes`. Before and after target hashes are derived from bytes read at those points. Event order is driver-authored; issuer fields inside those events are replies received from the issuer process.

Each case uses a fresh issuer process seeded with the same ticket and packet hash. That is not an identical issuer memory image.

## Claim ceiling

Proved by a `FIRST_BUILD_PASS` receipt: on this cooperating local pair, after a passing read and an acknowledged withdrawal, bind's fresh issuer read refused and the injected writer was not entered; the same bind without withdrawal entered the writer once and wrote the payload; a bind forced to reuse the earlier pass entered the writer after the same withdrawal.

Not proved: production security, hostile-issuer resistance, OS enforcement, cryptographic identity, atomic read-to-write protection, revocation after the final authority read, or how often this fails elsewhere. A and B do not present the earlier pass to bind.

Out of scope: evidence admission, replay protection, distributed or concurrent revocation, agent or framework machinery, certification, production readiness, and any claim that this is an inspection-class object.

The 2026-09-26 receipt is historical source evidence. It is not First Build evidence.
