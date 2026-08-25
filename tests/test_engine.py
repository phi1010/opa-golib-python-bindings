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


def test_multiple_engines_isolated():
    with OpaEngine() as a, OpaEngine() as b:
        a.add_data({"k": 1})
        b.add_data({"k": 2})
        assert a.eval_document("k") == 1
        assert b.eval_document("k") == 2
