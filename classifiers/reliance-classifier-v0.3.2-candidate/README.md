# Reliance classifier v0.3.2 — partial synthetic candidate

**Status: Partial synthetic classifier candidate — builder test records included.**

This directory holds a local classifier that reads preserved synthetic observations from the first-build receipt. It does not rerun the original control.

## Recorded results

On the unchanged preserved receipt, the builder cycle recorded:

- A and B: `NOT_CONTRADICTED_BY_THIS_OBSERVATION`.
- M: `CLAIM_CONTRADICTED` under deliberate cached-result reuse.

M is a deliberately unsafe sensitivity case. It is not evidence that the normal fresh-read path failed.

Modified regression inputs are classifier tests, not new control runs. A late withdrawal after a completed write returned `UNRESOLVED` in the builder suite.

## Evidence included

The package includes preserved observations, classifier source, tests, the classification rule and builder-generated result records.

`classify-run.txt` records the builder’s classifier execution.
`test-run.txt` records the builder’s test execution.
`classifier-output.txt` contains result lines written by the test script.

The reviewer-session receipt is not included. This publication therefore makes no reviewer-reproduction claim.

## Reproduction

Use a disposable local copy of this directory, keeping the published evidence files separately.

From that copy, run:

    python3 classify.py
    python3 test_classifier.py

The test command writes `classifier-output.txt` in its own directory and will replace an existing file of that name. Newly generated output is a reproduction result, not the preserved builder output.

## Limits

Revalidation-only and benign-change demonstrations remain outstanding. This is not the completed four-outcome specimen.

Passing the supplied tests does not establish complete classifier correctness.

This package makes no claim of operational performance, live pre-consequence detection or validation of wider research.

## Source and licence

Pinned control source:
`LalaSkye/bind-time-recheck` at
`7812759bd14535fd4e916cd0a009a4102d366ccf`.

The original first-build source and receipts remain unchanged.

MIT — see the [repository licence](../../LICENSE).
Copyright (c) 2026 Ricky Jones.
