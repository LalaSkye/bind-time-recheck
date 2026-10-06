# bind-time-recheck

A small synthetic Python fixture for one question:

**What happens if an earlier authority read passes, authority is then withdrawn, and bind either re-reads current authority or reuses the earlier pass?**

The repository preserves one accepted First Build under [`first-build/`](first-build/). It is a bounded test fixture, not a production security system or governance framework.

## First Build result

The preserved First Build contains three cases:

- **A — withdrawn:** the initial issuer read passes, withdrawal is acknowledged, bind performs a fresh issuer read, returns `authority_not_current`, writer entry count is `0`, and the target remains unchanged.
- **B — control:** no withdrawal occurs, bind performs a fresh issuer read, writer entry count is `1`, and the requested payload is written.
- **M — sensitivity:** after the same acknowledged withdrawal as A, bind is deliberately forced to reuse the earlier successful authority result. No fresh bind-time authority read occurs, writer entry count is `1`, and the payload is written. `SUBSTITUTION_VISIBLE` is sensitivity evidence, not protection evidence.

The two preserved First Build receipts differ only in `configuration.created_at`; their stable fields match.

## Run it

Python 3, standard library only.

```bash
cd first-build
python3 run.py
```

The run writes a new `receipt.json` and prints the same JSON. A new run is a reproduction attempt; it does not replace the two preserved First Build receipts.

## Evidence custody

`first-build/` preserves the accepted First Build bytes. Its [`SHA256SUMS`](first-build/SHA256SUMS) pins the four source files and the two preserved receipts.

Do not edit files inside `first-build/` and then describe the changed tree as the accepted First Build. A changed source tree is a new build and needs its own receipt and claim boundary.

## Claim ceiling

**Proved by this fixture:** on this cooperating local pair, after a passing read and an acknowledged withdrawal, normal bind's later issuer read refused and the injected writer was not entered; the same bind without withdrawal entered the writer once and wrote the payload; the same bind, forced to reuse the earlier pass, entered the writer after that withdrawal.

**Not proved:** production security, hostile-issuer resistance, OS enforcement, cryptographic identity, atomic read-to-write protection, revocation after the final authority read, or how often this failure occurs elsewhere. A and B do not present the earlier pass to bind.

**Out of scope:** evidence admission, replay protection, distributed or concurrent revocation, agent or framework machinery, certification, and production readiness.

## Repository layout

```text
bind-time-recheck/
├── README.md
├── LICENSE
├── SHA256SUMS
└── first-build/
    ├── README.md
    ├── issuer.py
    ├── gate.py
    ├── run.py
    ├── receipt-run1.json
    ├── receipt-run2.json
    └── SHA256SUMS
```

## Licence

MIT. See [`LICENSE`](LICENSE).
