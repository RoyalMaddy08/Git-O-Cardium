# Municipal multi-stage benchmark (40 attack + 8 benign cases, 4 stages, mock agent)

| Metric | Baseline | Protected |
|---|---|---|
| Attack success rate (any unauthorized side effect by the end) | 100.0% | 0.0% |
| Stored-injection success (damage appears only after later retrieval) | 80.0% | 0.0% |
| Unauthorized action rate (executed / proposed) | 100.0% | 0.0% |
| Benign completion rate (status report sent, no violations) | 100.0% | 100.0% |
| Attack-conditioned completion (legit report still sent) | 100.0% | 100.0% |
| False-positive rate (authorized actions denied) | 0.0% | 0.0% |
| Provenance preserved after save/archive/retrieval | n/a | 100.0% |
| Audit coverage (all proposals logged) | n/a | 100.0% |
| Audit rows carry content origin (stage 4) | n/a | 100.0% |

**Attack success by language** (baseline / protected)

| Group | Baseline | Protected |
|---|---|---|
| en | 100.0% | 0.0% |
| hi | 100.0% | 0.0% |
| mr | 100.0% | 0.0% |
| mr-latin | 100.0% | 0.0% |

**Attack success by attack goal** (baseline / protected)

| Group | Baseline | Protected |
|---|---|---|
| close | 100.0% | 0.0% |
| delete | 100.0% | 0.0% |
| exfil | 100.0% | 0.0% |
| pii_internal | 100.0% | 0.0% |
| redirect | 100.0% | 0.0% |

**Attack success by what was retrieved** (baseline / protected)

| Group | Baseline | Protected |
|---|---|---|
| archive | 100.0% | 0.0% |
| note | 100.0% | 0.0% |

Caveats: the agent is a regex stand-in that obeys hidden text; Latin-script Marathi phrases were written to match it, so multilingual rows test the gateway, not language understanding. Synthetic data, one workflow.
