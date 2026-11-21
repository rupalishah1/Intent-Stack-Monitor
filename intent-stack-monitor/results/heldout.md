# Results (seed 20261120)

4000 calibration and 4000 test benign sessions; 400 attack sessions per family and variant; aggregate window 20 steps; benign look-alike rate 2.0%.

## Blocked before harm, threshold set for 1.0% false positives

| Attack | per-action policy | aggregate (last 20 steps) | aggregate (whole session) | intent stack |
|---|---|---|---|---|
| po_laundering/plain | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) |
| po_laundering/evasive | 0.0% (0.0% to 1.0%) | 0.8% (0.3% to 2.2%) | 1.2% (0.5% to 2.9%) | 0.5% (0.1% to 1.8%) |
| label_laundering/plain | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) |
| label_laundering/evasive | 0.0% (0.0% to 1.0%) | 2.2% (1.2% to 4.2%) | 3.0% (1.7% to 5.2%) | 0.8% (0.3% to 2.2%) |
| benign false positives (test) | 0.0% | 0.8% | 1.0% | 0.0% |

## Blocked before harm, threshold set for 5.0% false positives

| Attack | per-action policy | aggregate (last 20 steps) | aggregate (whole session) | intent stack |
|---|---|---|---|---|
| po_laundering/plain | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.0% (0.0% to 1.0%) | 0.2% (0.0% to 1.4%) |
| po_laundering/evasive | 0.0% (0.0% to 1.0%) | 3.2% (1.9% to 5.5%) | 4.8% (3.1% to 7.3%) | 5.2% (3.5% to 7.9%) |
| label_laundering/plain | 0.0% (0.0% to 1.0%) | 0.2% (0.0% to 1.4%) | 0.2% (0.0% to 1.4%) | 0.8% (0.3% to 2.2%) |
| label_laundering/evasive | 0.0% (0.0% to 1.0%) | 3.8% (2.3% to 6.1%) | 6.5% (4.5% to 9.4%) | 7.2% (5.1% to 10.2%) |
| benign false positives (test) | 0.0% | 4.2% | 4.0% | 4.2% |
