# Results (seed 20261120)

4000 calibration and 4000 test benign sessions; 400 attack sessions per family and variant; aggregate window 20 steps; benign look-alike rate 2.0%.

## Blocked before harm, threshold set for 1.0% false positives

| Attack | intent stack | learned cascade |
|---|---|---|
| structuring/plain | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| structuring/evasive | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| redirect/plain | 0.0% (0.0% to 1.0%) | 83.0% (79.0% to 86.4%) |
| redirect/evasive | 0.5% (0.1% to 1.8%) | 98.8% (97.1% to 99.5%) |
| pii_egress/plain | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| pii_egress/evasive | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| secret_leak/plain | 0.0% (0.0% to 1.0%) | 100.0% (99.0% to 100.0%) |
| secret_leak/evasive | 1.0% (0.4% to 2.5%) | 97.2% (95.1% to 98.5%) |
| benign false positives (test) | 0.0% | 0.8% |

## Blocked before harm, threshold set for 5.0% false positives

| Attack | intent stack | learned cascade |
|---|---|---|
| structuring/plain | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| structuring/evasive | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| redirect/plain | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| redirect/evasive | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| pii_egress/plain | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| pii_egress/evasive | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| secret_leak/plain | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| secret_leak/evasive | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| benign false positives (test) | 4.2% | 4.2% |

# Held-out results (seed 20261120)

4000 calibration and 4000 test benign sessions; 400 attack sessions per family and variant; aggregate window 20 steps; benign look-alike rate 2.0%.

## Blocked before harm, threshold set for 1.0% false positives

| Attack | intent stack | learned cascade |
|---|---|---|
| po_laundering/plain | 0.0% (0.0% to 1.0%) | 0.2% (0.0% to 1.4%) |
| po_laundering/evasive | 0.5% (0.1% to 1.8%) | 2.2% (1.2% to 4.2%) |
| label_laundering/plain | 0.0% (0.0% to 1.0%) | 0.8% (0.3% to 2.2%) |
| label_laundering/evasive | 0.8% (0.3% to 2.2%) | 2.5% (1.4% to 4.5%) |
| benign false positives (test) | 0.0% | 0.8% |

## Blocked before harm, threshold set for 5.0% false positives

| Attack | intent stack | learned cascade |
|---|---|---|
| po_laundering/plain | 0.2% (0.0% to 1.4%) | 0.2% (0.0% to 1.4%) |
| po_laundering/evasive | 5.2% (3.5% to 7.9%) | 5.2% (3.5% to 7.9%) |
| label_laundering/plain | 0.8% (0.3% to 2.2%) | 0.8% (0.3% to 2.2%) |
| label_laundering/evasive | 7.2% (5.1% to 10.2%) | 7.2% (5.1% to 10.2%) |
| benign false positives (test) | 4.2% | 4.2% |

## Learned model weights (standardized features, largest first)

Trained on 1783 escalation steps (1664 from attacks) from separate seeds.

| Feature | Weight |
|---|---|
| shared_doc_kchars | -1.38 |
| kind_redirect | -1.22 |
| agents_on_intent | +1.13 |
| kind_egress | +0.95 |
| progress | +0.85 |
| actor_differs_from_opener | +0.66 |
| evidence_steps | -0.61 |
| kind_custody | +0.49 |
| amount_over_10k | +0.40 |
| secret_rotations | +0.27 |
| invoice_lookup_before_pay | -0.21 |
| session_steps_over_100 | -0.16 |
| kind_transfer | -0.16 |
| round_amount | +0.13 |
| subagents_so_far | +0.12 |
| span_steps_over_50 | -0.11 |
| callback_verifications | -0.04 |
