# Results (seed 20261120)

4000 calibration and 4000 test benign sessions; 400 attack sessions per family and variant; aggregate window 20 steps; benign look-alike rate 2.0%.

## Blocked before harm, threshold set for 1.0% false positives

| Attack | per-action policy | aggregate (last 20 steps) | aggregate (whole session) | intent stack |
|---|---|---|---|---|
| structuring/plain | 0.0% (0.0% to 1.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| structuring/evasive | 0.0% (0.0% to 1.0%) | 0.5% (0.1% to 1.8%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| redirect/plain | 0.0% (0.0% to 1.0%) | 0.2% (0.0% to 1.4%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) |
| redirect/evasive | 0.0% (0.0% to 1.0%) | 1.2% (0.5% to 2.9%) | 1.0% (0.4% to 2.5%) | 0.5% (0.1% to 1.8%) |
| pii_egress/plain | 0.0% (0.0% to 1.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| pii_egress/evasive | 0.0% (0.0% to 1.0%) | 0.8% (0.3% to 2.2%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| secret_leak/plain | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) |
| secret_leak/evasive | 0.0% (0.0% to 1.0%) | 0.8% (0.3% to 2.2%) | 2.0% (1.0% to 3.9%) | 1.0% (0.4% to 2.5%) |
| benign false positives (test) | 0.0% | 0.8% | 1.0% | 0.0% |

## Blocked before harm, threshold set for 5.0% false positives

| Attack | per-action policy | aggregate (last 20 steps) | aggregate (whole session) | intent stack |
|---|---|---|---|---|
| structuring/plain | 0.0% (0.0% to 1.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| structuring/evasive | 0.0% (0.0% to 1.0%) | 2.2% (1.2% to 4.2%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| redirect/plain | 0.0% (0.0% to 1.0%) | 0.8% (0.3% to 2.2%) | 0.2% (0.0% to 1.4%) | 100.0% (99.0% to 100.0%) |
| redirect/evasive | 0.0% (0.0% to 1.0%) | 3.0% (1.7% to 5.2%) | 3.2% (1.9% to 5.5%) | 100.0% (99.0% to 100.0%) |
| pii_egress/plain | 0.0% (0.0% to 1.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| pii_egress/evasive | 0.0% (0.0% to 1.0%) | 3.2% (1.9% to 5.5%) | 100.0% (99.0% to 100.0%) | 100.0% (99.0% to 100.0%) |
| secret_leak/plain | 0.0% (0.0% to 1.0%) | 0.2% (0.0% to 1.4%) | 0.2% (0.0% to 1.4%) | 100.0% (99.0% to 100.0%) |
| secret_leak/evasive | 0.0% (0.0% to 1.0%) | 2.5% (1.4% to 4.5%) | 5.2% (3.5% to 7.9%) | 100.0% (99.0% to 100.0%) |
| benign false positives (test) | 0.0% | 4.2% | 4.0% | 4.2% |

## Intent stack vs. benign look-alike rate (threshold for 1% false positives)

| Look-alike rate | redirect/plain | redirect/evasive | secret_leak/plain | secret_leak/evasive | benign false positives |
|---|---|---|---|---|---|
| 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.7% |
| 1.0% | 0.0% | 0.7% | 0.0% | 0.3% | 0.0% |
| 2.0% | 0.0% | 0.7% | 0.0% | 0.3% | 0.0% |
| 5.0% | 0.0% | 0.7% | 0.0% | 0.3% | 0.0% |
