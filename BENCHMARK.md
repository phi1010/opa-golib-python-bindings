# Benchmark

Bindings benchmarked against OPA's official test suite: the YAML
compliance corpus shipped in the OPA Go module (`v1/test/cases/testdata/v1`,
OPA v1.19.1) — the same cases OPA uses to validate its own evaluators.

- Date: 2026-08-27
- Machine: Linux 6.14.0-1019-oem (x86_64), Python 3.14.3, go version go1.26.0 linux/amd64
- Cases: 6057 run and compared, 6057 verified correct, 0 mismatched. Not compared: 48 strict-mode divergences (the engine always sets `StrictBuiltinErrors`, the suite expects non-strict semantics unless marked `strict_error`), 408 unsupported (experimental future keywords the bridge's parser does not enable), 258 skipped (environment-dependent/nondeterministic categories, non-JSON input terms, expected-error cases that would need message comparison)
- Sweep wall time: 4.5 s (1340 cases/s incl. engine setup and verification)

Each case builds a fresh engine. Phases:

- **setup** — engine creation + `add_policy`/`add_data` (Rego parse)
- **first eval** — `eval_query` on a fresh engine (compile/`PrepareForEval` + evaluation + JSON round-trip)
- **cached eval** — the same `eval_query` again (prepared-query cache hit + evaluation + JSON round-trip)

| phase | mean ms | p50 ms | p90 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| setup | 0.10 | 0.06 | 0.19 | 0.68 | 9.80 |
| first eval | 0.53 | 0.36 | 1.05 | 2.61 | 14.90 |
| cached eval | 0.07 | 0.03 | 0.11 | 0.59 | 9.49 |

Cached evaluation throughput: 14373 evals/s single-threaded (dominated by per-eval overhead: ctypes call + JSON encode/decode across the C boundary).

## Slowest categories (mean first eval)

| category | cases | mean first ms | mean cached ms |
|---|---|---|---|
| cryptox509parsekeypair | 6 | 2.88 | 1.97 |
| baseandvirtualdocs | 30 | 2.51 | 0.08 |
| functions | 99 | 2.00 | 0.04 |
| cryptox509parseandverifycertificates | 6 | 1.69 | 0.82 |
| jwtencodesign | 18 | 1.42 | 0.37 |
| inputvalues | 18 | 1.26 | 0.05 |
| cryptox509parsersaprivatekey | 6 | 1.08 | 0.46 |
| jwtverifyrsa | 117 | 1.07 | 0.55 |
| cryptox509parsecertificates | 30 | 1.02 | 0.38 |
| compositereferences | 45 | 1.00 | 0.06 |

## Correctness

6057/6057 cases produce results identical to OPA's expected output (order-insensitive result-set comparison; error cases count as correct when the bindings raise an error as expected).

Unsupported (parse errors, counted separately): logic_operators (408).

Strict-mode divergences by category: baseandvirtualdocs (3), functionerrors (3), jsonpatch (9), regexmatch (3), regexreplace (3), strings (18), subset (6), withkeyword (3).

Reproduce with: `.venv/bin/python benchmarks/bench.py`
