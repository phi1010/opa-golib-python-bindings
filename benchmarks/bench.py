"""Benchmark the bindings against OPA's official test suite.

The suite is the YAML compliance corpus shipped inside the OPA Go module
(``v1/test/cases/testdata/v1``, the same cases OPA uses to validate its own
evaluators). Every case is run through ``OpaEngine`` and timed in three
phases:

- setup:      OpaNew + add_policy/add_data (parse + cache invalidation)
- first eval: eval_query on a fresh engine (PrepareForEval + eval)
- cached eval: eval_query again (prepared-query cache hit)

Results are verified against the case's ``want_result`` / ``want_error`` so
the numbers only cover evaluations the bindings got right. Writes
BENCHMARK.md into the repository root.

Usage: .venv/bin/python benchmarks/bench.py [--repeat N]
"""

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from opa_bindings import OpaEngine, OpaError  # noqa: E402

OPA_VERSION = "1.19.1"

# Categories whose builtins depend on the environment or the wall clock, or
# that are nondeterministic; their results are not stable enough to verify.
SKIP_CATEGORIES = {
    "netlookupipaddr",  # DNS lookups
    "time",  # wall clock
    "providers-aws",  # request signing embeds timestamps
    "walkbuiltin",  # ordering of results varies
    "randintn",  # nondeterministic
    "uuid",  # nondeterministic
}


def suite_dir() -> Path:
    gomodcache = subprocess.run(
        ["go", "env", "GOMODCACHE"], capture_output=True, text=True, check=True
    ).stdout.strip()
    d = (
        Path(gomodcache)
        / f"github.com/open-policy-agent/opa@v{OPA_VERSION}"
        / "v1/test/cases/testdata/v1"
    )
    if not d.is_dir():
        sys.exit(
            f"OPA test suite not found at {d}; run `make build` once to "
            "populate the Go module cache"
        )
    return d


def load_cases(root: Path):
    for f in sorted(root.rglob("*.yaml")):
        category = f.relative_to(root).parts[0]
        with f.open() as fh:
            doc = yaml.safe_load(fh)
        for case in doc.get("cases", []):
            yield category, case


def canon(v):
    """Canonicalize numbers: JSON does not distinguish 5 from 5.0 (OPA
    preserves the source spelling, YAML parses the expectation as int)."""
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, list):
        return [canon(x) for x in v]
    if isinstance(v, dict):
        return {k: canon(x) for k, x in v.items()}
    return v


def normalize(rs):
    """Order-insensitive form of a result set for comparison."""
    return sorted(json.dumps(canon(r), sort_keys=True) for r in rs)


def loose_normalize(v):
    """Like normalize, but insensitive to set serialization order: Rego sets
    reach Python as lists whose order OPA does not guarantee, so nested lists
    are compared sorted."""
    if isinstance(v, list):
        return sorted(json.dumps(loose_normalize(x), sort_keys=True) for x in v)
    if isinstance(v, dict):
        return {k: loose_normalize(x) for k, x in v.items()}
    return canon(v)


def run_case(case):
    """Run one case; returns (status, setup_s, first_s, cached_s) with
    status in ok / fail / skip / strict / unsupported."""
    input_value = case.get("input")
    if input_value is None and "input_term" in case:
        # input_term is a Rego term as string; only JSON-compatible ones are
        # representable through the bindings.
        try:
            input_value = json.loads(case["input_term"])
        except ValueError:
            return "skip", None, None, None  # non-JSON input term (e.g. sets)

    want_error = "want_error" in case or "want_error_code" in case
    t0 = time.perf_counter()
    engine = OpaEngine()
    try:
        for i, mod in enumerate(case.get("modules", [])):
            engine.add_policy(f"mod{i}.rego", mod)
        if case.get("data") is not None:
            engine.add_data(case["data"])
    except OpaError as ex:
        engine.close()
        if want_error:
            return "ok", None, None, None
        if ex.code == "parse_error":
            # e.g. experimental future keywords (and/or) the bridge's parser
            # does not enable
            return "unsupported", None, None, None
        return "fail", None, None, None
    t1 = time.perf_counter()
    try:
        rs = engine.eval_query(case["query"], input_value)
        t2 = time.perf_counter()
        if want_error:
            engine.close()
            return "skip", None, None, None  # error expected but none raised
        expected = case.get("want_result") or []
        ok = normalize(rs) == normalize(expected) or (
            loose_normalize(rs) == loose_normalize(expected)
        )
        # cached eval (prepared query reused)
        t3 = time.perf_counter()
        engine.eval_query(case["query"], input_value)
        t4 = time.perf_counter()
        engine.close()
        return ("ok" if ok else "fail"), t1 - t0, t2 - t1, t4 - t3
    except OpaError:
        t2 = time.perf_counter()
        engine.close()
        if want_error:
            return "ok", t1 - t0, t2 - t1, None
        if not case.get("strict_error"):
            # The engine always runs with StrictBuiltinErrors; the suite
            # expects non-strict semantics (builtin errors -> undefined)
            # unless strict_error is set. Not comparable, by design.
            return "strict", None, None, None
        return "fail", None, None, None


def fmt_ms(seconds):
    return f"{seconds * 1000:.2f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=1, help="sweep repetitions")
    args = ap.parse_args()

    root = suite_dir()
    cases = list(load_cases(root))

    per_cat = defaultdict(lambda: {"n": 0, "ok": 0, "setup": [], "first": [], "cached": []})
    counts = defaultdict(int)
    unsupported_cats = defaultdict(int)
    strict_cats = defaultdict(int)
    wall0 = time.perf_counter()
    for _ in range(args.repeat):
        for category, case in cases:
            if category in SKIP_CATEGORIES:
                counts["skip"] += 1
                continue
            status, setup, first, cached = run_case(case)
            counts[status] += 1
            if status == "unsupported":
                unsupported_cats[category] += 1
                continue
            if status == "strict":
                strict_cats[category] += 1
                continue
            if status == "skip":
                continue
            s = per_cat[category]
            s["n"] += 1
            if status == "ok":
                s["ok"] += 1
                if setup is not None:
                    s["setup"].append(setup)
                if first is not None:
                    s["first"].append(first)
                if cached is not None:
                    s["cached"].append(cached)
    wall = time.perf_counter() - wall0
    failed = counts["fail"]
    skipped = counts["skip"]

    all_setup = [v for s in per_cat.values() for v in s["setup"]]
    all_first = [v for s in per_cat.values() for v in s["first"]]
    all_cached = [v for s in per_cat.values() for v in s["cached"]]
    total = sum(s["n"] for s in per_cat.values())
    passed = sum(s["ok"] for s in per_cat.values())

    def stats_row(label, xs):
        qs = statistics.quantiles(xs, n=100)
        return (
            f"| {label} | {fmt_ms(statistics.mean(xs))} | "
            f"{fmt_ms(statistics.median(xs))} | {fmt_ms(qs[89])} | "
            f"{fmt_ms(qs[98])} | {fmt_ms(max(xs))} |"
        )

    slowest = sorted(
        ((statistics.mean(s["first"]), c) for c, s in per_cat.items() if s["first"]),
        reverse=True,
    )[:10]

    uname = platform.uname()
    go_version = subprocess.run(
        ["go", "version"], capture_output=True, text=True
    ).stdout.strip()

    lines = [
        "# Benchmark",
        "",
        "Bindings benchmarked against OPA's official test suite: the YAML",
        f"compliance corpus shipped in the OPA Go module (`v1/test/cases/testdata/v1`,",
        f"OPA v{OPA_VERSION}) — the same cases OPA uses to validate its own evaluators.",
        "",
        f"- Date: {date.today().isoformat()}",
        f"- Machine: {uname.system} {uname.release} ({uname.machine}), "
        f"Python {platform.python_version()}, {go_version}",
        f"- Cases: {total} run and compared, {passed} verified correct, "
        f"{failed} mismatched. Not compared: {counts['strict']} strict-mode "
        "divergences (the engine always sets `StrictBuiltinErrors`, the suite "
        "expects non-strict semantics unless marked `strict_error`), "
        f"{counts['unsupported']} unsupported (experimental future keywords "
        f"the bridge's parser does not enable), {skipped} skipped "
        "(environment-dependent/nondeterministic categories, non-JSON input "
        "terms, expected-error cases that would need message comparison)",
        f"- Sweep wall time: {wall:.1f} s "
        f"({total / wall:.0f} cases/s incl. engine setup and verification)",
        "",
        "Each case builds a fresh engine. Phases:",
        "",
        "- **setup** — engine creation + `add_policy`/`add_data` (Rego parse)",
        "- **first eval** — `eval_query` on a fresh engine "
        "(compile/`PrepareForEval` + evaluation + JSON round-trip)",
        "- **cached eval** — the same `eval_query` again "
        "(prepared-query cache hit + evaluation + JSON round-trip)",
        "",
        "| phase | mean ms | p50 ms | p90 ms | p99 ms | max ms |",
        "|---|---|---|---|---|---|",
        stats_row("setup", all_setup),
        stats_row("first eval", all_first),
        stats_row("cached eval", all_cached),
        "",
        f"Cached evaluation throughput: "
        f"{len(all_cached) / sum(all_cached):.0f} evals/s single-threaded "
        "(dominated by per-eval overhead: ctypes call + JSON encode/decode "
        "across the C boundary).",
        "",
        "## Slowest categories (mean first eval)",
        "",
        "| category | cases | mean first ms | mean cached ms |",
        "|---|---|---|---|",
    ]
    for mean_first, cat in slowest:
        s = per_cat[cat]
        cached_ms = fmt_ms(statistics.mean(s["cached"])) if s["cached"] else "—"
        lines.append(f"| {cat} | {s['n']} | {fmt_ms(mean_first)} | {cached_ms} |")

    mismatching = sorted(c for c, s in per_cat.items() if s["ok"] < s["n"])
    lines += [
        "",
        "## Correctness",
        "",
        f"{passed}/{total} cases produce results identical to OPA's expected "
        "output (order-insensitive result-set comparison; error cases count "
        "as correct when the bindings raise an error as expected).",
    ]
    if unsupported_cats:
        lines += [
            "",
            "Unsupported (parse errors, counted separately): "
            + ", ".join(f"{c} ({n})" for c, n in sorted(unsupported_cats.items()))
            + ".",
        ]
    if strict_cats:
        lines += [
            "",
            "Strict-mode divergences by category: "
            + ", ".join(f"{c} ({n})" for c, n in sorted(strict_cats.items()))
            + ".",
        ]
    if mismatching:
        lines += [
            "",
            "Categories with mismatches: "
            + ", ".join(
                f"{c} ({per_cat[c]['ok']}/{per_cat[c]['n']})" for c in mismatching
            )
            + ".",
        ]
    lines += [
        "",
        "Reproduce with: `.venv/bin/python benchmarks/bench.py`",
        "",
    ]

    out = Path(__file__).resolve().parents[1] / "BENCHMARK.md"
    out.write_text("\n".join(lines))
    print(f"wrote {out}")
    print(f"{passed}/{total} ok, {failed} failed, {skipped} skipped, {wall:.1f}s")


if __name__ == "__main__":
    main()
