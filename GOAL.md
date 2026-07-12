# Goal & Evaluation Rubric (loop engineering contract)

**Mission:** turn WebFusion into a **shift-left DevSecOps** tool — catch web
security issues in the *dev/CI* stage, not in production. The interactive proxy
(Repeater/Fuzzer/Intercept) stays as the local "left-of-runtime" surface; on top
of it we add an **automated, headless, CI-first scanner** with machine-readable
output and a deployable dashboard.

## Definition of done — the loop stops when the eval score is ≥ 90/100

The self-eval (`eval/run_eval.py`) scans a deliberately-vulnerable local app and
a clean target, then scores six dimensions (weights in parentheses):

| # | Dimension | What "good" means | Weight |
|---|-----------|-------------------|:------:|
| 1 | **Detection recall** | finds the seeded vulns in the vulnerable app | 25 |
| 2 | **Precision** | no findings against the clean target (no false positives) | 20 |
| 3 | **Shift-left fit** | SARIF + JSON output, non-zero exit on `--fail-on`, GitHub Action | 20 |
| 4 | **Safety** | SSRF guard, passive-only public mode, scope + authz warnings, bounded requests | 15 |
| 5 | **Deployability** | dashboard runs; Vercel handler imports & serves; deploy docs | 10 |
| 6 | **Usability** | severity, confidence, evidence, remediation, CWE on every finding | 10 |

Each dimension scored 0–100; total is the weighted average. The loop iterates
build → eval → fix until total ≥ 90 and dimensions 1–2 are each ≥ 85.

## Non-negotiable safety rules

- **Public/deployed scanner is passive-only.** Active payload injection is
  available **only** via the local CLI (`--active`), never from the hosted site.
- **SSRF guard:** the hosted scanner refuses localhost, private, and link-local
  address ranges.
- Every scan surfaces an "authorized targets only" warning.
