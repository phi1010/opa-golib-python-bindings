import pytest

from opa_bindings import OpaEngine, OpaError, OpaUndefinedError

AUTHZ = """
package example.authz

default allow := false

allow if {
    input.method == "GET"
    input.path == ["salary", input.subject.user]
}

allow if "admin" in input.subject.groups
"""


@pytest.fixture
def engine():
    with OpaEngine() as e:
        yield e


def test_eval_document_allow_deny(engine):
    engine.add_policy("authz.rego", AUTHZ)
    assert engine.eval_document(
        "example.authz.allow",
        {"method": "GET", "path": ["salary", "bob"], "subject": {"user": "bob"}},
    ) is True
    assert engine.eval_document(
        "example.authz.allow",
        {"method": "POST", "path": [], "subject": {"user": "bob"}},
    ) is False


def test_eval_query_bindings(engine):
    engine.add_policy("nums.rego", "package nums\n\nvalues := [1, 2, 3]\n")
    rows = engine.eval_query("x = data.nums.values[_]")
    assert [r["x"] for r in rows] == [1, 2, 3]


def test_data_deep_merge(engine):
    engine.add_data({"roles": {"admin": ["alice"]}})
    engine.add_data({"bob": "viewer"}, path="users")
    engine.add_data({"roles": {"editor": ["carol"]}})
    assert engine.eval_document("") == {
        "roles": {"admin": ["alice"], "editor": ["carol"]},
        "users": {"bob": "viewer"},
    }


def test_data_merge_conflict(engine):
    engine.add_data({"a": {"b": 1}})
    engine.add_data({"a": {"b": 1}})  # identical value is fine
    with pytest.raises(OpaError) as ei:
        engine.add_data({"a": {"b": 2}})
    assert ei.value.code == "merge_conflict"
    assert "data.a.b" in ei.value.message


def test_builtin_arities(engine):
    engine.register_function("zero", lambda: 42)
    engine.register_function("one", lambda x: x * 2)
    engine.register_function("two", lambda x, y: {"sum": x + y})
    engine.register_function("many", lambda *args: list(args))
    engine.add_policy(
        "b.rego",
        """
package b

r0 := zero()
r1 := one(21)
r2 := two(1, 2)
r3 := many(["a", "b", "c"])
""",
    )
    assert engine.eval_document("b") == {
        "r0": 42,
        "r1": 42,
        "r2": {"sum": 3},
        "r3": ["a", "b", "c"],
    }


def test_builtin_fetches_python_data(engine):
    users = {"alice": {"role": "admin"}, "bob": {"role": "viewer"}}
    engine.register_function("lookup_user", lambda name: users.get(name))
    engine.add_policy(
        "u.rego",
        """
package u

allow if lookup_user(input.user).role == "admin"
""",
    )
    assert engine.eval_document("u.allow", {"user": "alice"}) is True
    with pytest.raises(OpaUndefinedError):
        engine.eval_document("u.allow", {"user": "bob"})


def test_builtin_exception_is_eval_error(engine):
    def boom(x):
        raise ValueError("nope")

    engine.register_function("boom", boom)
    engine.add_policy("e.rego", "package e\n\nr := boom(1)\n")
    with pytest.raises(OpaError) as ei:
        engine.eval_document("e.r")
    assert ei.value.code == "eval_error"
    assert "nope" in ei.value.message


def test_invalid_policy(engine):
    with pytest.raises(OpaError) as ei:
        engine.add_policy("bad.rego", "this is not rego")
    assert ei.value.code == "parse_error"


def test_undefined_document(engine):
    engine.add_policy("p.rego", "package p\n\nx := 1\n")
    with pytest.raises(OpaUndefinedError):
        engine.eval_document("p.missing")


def test_print_capture(engine):
    engine.add_policy(
        "pr.rego",
        """
package pr

r := x if {
    print("computing for", input.n)
    x := input.n * 2
}
""",
    )
    captured = []
    engine.print_handler = lambda msg, loc: captured.append((msg, loc))
    assert engine.eval_document("pr.r", {"n": 3}) == 6
    assert captured == engine.last_prints
    (msg, loc), = captured
    assert msg == "computing for 3"
    assert "pr.rego" in loc


def test_coverage_capture(engine):
    engine.add_policy(
        "cov.rego",
        """
package cov

a := 1

b := 2 if {
    input.flag
}
""",
    )
    assert engine.last_coverage is None
    assert engine.eval_document("cov", {"flag": False}) == {"a": 1}
    assert engine.last_coverage is None  # coverage off by default

    assert engine.eval_document("cov", {"flag": False}, coverage=True) == {"a": 1}
    report = engine.last_coverage
    fr = report["files"]["cov.rego"]
    def rows(ranges):
        return {row for r in ranges for row in range(r["start"]["row"], r["end"]["row"] + 1)}

    assert 4 in rows(fr["covered"])  # a := 1
    assert 7 in rows(fr["covered"])  # input.flag was evaluated (to false)
    assert 6 in rows(fr["not_covered"])  # rule head of b never succeeded
    assert 0 < report["coverage"] < 100

    engine.eval_document("cov", {"flag": True}, coverage=True)
    fr = engine.last_coverage["files"]["cov.rego"]
    assert not fr.get("not_covered")
    assert engine.last_coverage["coverage"] == 100

    # a subsequent eval without coverage clears the report
    engine.eval_document("cov", {"flag": True})
    assert engine.last_coverage is None

    # a failed eval does not leave a stale report behind
    engine.eval_document("cov", {"flag": True}, coverage=True)
    engine.register_function("boom_cov", lambda: 1 / 0)
    engine.add_policy("boom.rego", "package boom\n\nr := boom_cov()\n")
    with pytest.raises(OpaError):
        engine.eval_document("boom.r", coverage=True)
    assert engine.last_coverage is None


def test_trace_capture(engine):
    engine.add_policy(
        "t.rego",
        """
package t

r := x if {
    x := input.n * 2
    x > 3
}
""",
    )
    assert engine.eval_document("t.r", {"n": 3}) == 6
    assert engine.last_trace is None  # trace off by default

    assert engine.eval_document("t.r", {"n": 3}, trace=True) == 6
    trace = engine.last_trace
    assert trace and all("op" in ev for ev in trace)
    # The rule body was entered and exited (the rule succeeded) ...
    rule_events = [ev for ev in trace if ev.get("location", "").startswith("t.rego:")]
    assert any(ev["op"] == "Exit" for ev in rule_events)
    # ... and the bound value of x is visible in the event locals.
    assert any(ev.get("locals", {}).get("x") == 6 for ev in rule_events)
    # Compiler temporaries are filtered out of locals.
    assert not any(
        name.startswith(("__local", "$"))
        for ev in trace
        for name in ev.get("locals", {})
    )

    # A failing condition shows up as a Fail event at its location.
    with pytest.raises(OpaUndefinedError):
        engine.eval_document("t.r", {"n": 1}, trace=True)
    assert any(ev["op"] == "Fail" for ev in engine.last_trace)

    engine.eval_document("t.r", {"n": 3})
    assert engine.last_trace is None


def test_multiple_engines_isolated():
    with OpaEngine() as a, OpaEngine() as b:
        a.add_data({"k": 1})
        b.add_data({"k": 2})
        assert a.eval_document("k") == 1
        assert b.eval_document("k") == 2
