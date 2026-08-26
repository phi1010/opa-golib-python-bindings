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


FILTERS = """
package filters

include if input.fruits.colour == "green"

include if {
    input.fruits.name == "banana"
    input.user == "admin"
}
"""


def test_compile_filters_sql(engine):
    engine.add_policy("filters.rego", FILTERS)
    result = engine.compile_filters(
        "data.filters.include",
        {"user": "admin"},
        unknowns=["input.fruits"],
        target="sql",
        dialect="postgresql",
    )
    # The OR branches come from separate rules; their order is not guaranteed.
    assert result["query"] in (
        "WHERE (fruits.colour = E'green' OR fruits.name = E'banana')",
        "WHERE (fruits.name = E'banana' OR fruits.colour = E'green')",
    )
    assert result["masks"] is None


def test_compile_filters_ucast(engine):
    engine.add_policy("filters.rego", FILTERS)
    result = engine.compile_filters(
        "data.filters.include",
        {"user": "nobody"},
        unknowns=["input.fruits"],
        target="ucast",
        dialect="prisma",
    )
    assert result["query"] == {
        "type": "field",
        "field": "fruits.colour",
        "operator": "eq",
        "value": "green",
    }


def test_compile_filters_mappings(engine):
    engine.add_policy("filters.rego", FILTERS)
    result = engine.compile_filters(
        "data.filters.include",
        {"user": "nobody"},
        unknowns=["input.fruits"],
        target="sql",
        dialect="sqlite",
        mappings={"fruits": {"$self": "f", "colour": "col"}},
    )
    assert result["query"] == "WHERE f.col = 'green'"


def test_compile_filters_never_and_always(engine):
    engine.add_policy("filters.rego", FILTERS)
    # No rule can match: query is None (never satisfied).
    never = engine.compile_filters(
        "data.filters.no_such_rule",
        unknowns=["input.fruits"],
    )
    assert never["query"] is None
    # Trivially true query: empty WHERE clause (always satisfied).
    always = engine.compile_filters("1 == 1", unknowns=["input.fruits"])
    assert always["query"] == ""


def test_compile_filters_untranslatable(engine):
    engine.add_policy(
        "bad.rego",
        'package bad\n\ninclude if regex.match("^a", input.fruits.name)\n',
    )
    with pytest.raises(OpaError) as exc:
        engine.compile_filters("data.bad.include", unknowns=["input.fruits"])
    assert exc.value.code == "compile_error"


# An EAV (entity-attribute-value) database delivers rows like
# attr(entity_id, key, type, value_string, value_number, value_bool,
# value_de, value_en, ...): one typed value column per datatype and one
# localized value column per locale. The filter translator only accepts refs
# of the form <unknown>.<column>, so policies address these flat columns; the
# locale (and hence the column) is picked dynamically from the known input.
EAV = """
package eav

# Localized match: the value column is chosen by the requested locale.
include if input.attr[sprintf("value_%s", [input.locale])] == "Banane"

# Typed match: numeric comparison guarded by the datatype tag.
include if {
    input.attr.type == "number"
    input.attr.value_number < 10
}

# Differing datatypes: boolean and null-valued attributes.
include if input.attr.value_bool == true
include if input.attr.value_string == null
"""


def test_compile_filters_eav_sql(engine):
    engine.add_policy("eav.rego", EAV)
    result = engine.compile_filters(
        "data.eav.include",
        {"locale": "de"},
        unknowns=["input.attr"],
        target="sql",
        dialect="postgresql",
    )
    clauses = result["query"].removeprefix("WHERE (").removesuffix(")").split(" OR ")
    assert sorted(clauses) == [
        "(attr.type = E'number' AND attr.value_number < E'10')",
        "attr.value_bool = TRUE",
        "attr.value_de = E'Banane'",
        "attr.value_string IS NULL",
    ]
    # A different locale selects a different column.
    result = engine.compile_filters(
        "data.eav.include",
        {"locale": "en"},
        unknowns=["input.attr"],
        target="sql",
        dialect="postgresql",
    )
    assert "attr.value_en = E'Banane'" in result["query"]
    assert "value_de" not in result["query"]


def test_compile_filters_eav_ucast(engine):
    engine.add_policy("eav.rego", EAV)
    result = engine.compile_filters(
        "data.eav.include",
        {"locale": "de"},
        unknowns=["input.attr"],
        target="ucast",
        dialect="prisma",
    )
    top = result["query"]
    assert top["type"] == "compound" and top["operator"] == "or"
    leaves = {}
    for cond in top["value"]:
        conds = cond["value"] if cond["type"] == "compound" else [cond]
        for c in conds:
            leaves[(c["field"], c["operator"])] = c["value"]
    # Datatypes survive as native JSON types (no stringification as in SQL).
    assert leaves == {
        ("attr.value_de", "eq"): "Banane",
        ("attr.type", "eq"): "number",
        ("attr.value_number", "lt"): 10,
        ("attr.value_bool", "eq"): True,
        ("attr.value_string", "eq"): None,
    }


def test_compile_filters_eav_entity_attribute_join(engine):
    # The classic two-table EAV shape: entities joined to attribute rows.
    engine.add_policy(
        "join.rego",
        """
        package join

        include if {
            input.item.id == input.attr.entity_id
            input.attr.key == "name"
            input.attr.value_de == "Banane"
        }
        """,
    )
    result = engine.compile_filters(
        "data.join.include",
        unknowns=["input.item", "input.attr"],
        target="sql",
        dialect="postgresql",
    )
    assert result["query"] == (
        "WHERE (item.id = attr.entity_id AND attr.key = E'name'"
        " AND attr.value_de = E'Banane')"
    )


def test_compile_filters_eav_localized_from_data(engine):
    # Translations stored as data: iterating them ORs all localized spellings.
    engine.add_policy(
        "loc.rego",
        "package loc\n\ninclude if input.attr.value == data.translations.banana[_]\n",
    )
    engine.add_data({"banana": {"de": "Banane", "en": "banana"}}, path="translations")
    result = engine.compile_filters(
        "data.loc.include", unknowns=["input.attr"], target="sql", dialect="sqlite"
    )
    assert sorted(result["query"].removeprefix("WHERE (").removesuffix(")").split(" OR ")) == [
        "attr.value = 'Banane'",
        "attr.value = 'banana'",
    ]


def test_compile_filters_eav_nested_document_unsupported(engine):
    # A document-shaped EAV input ({"attrs": {"price": {"type": ..., "value":
    # ...}}}) cannot be translated: only refs of the exact shape
    # input.<table>.<column> are accepted, for every target/dialect
    # (ucast/all included). Flatten to columns (as above) instead.
    engine.add_policy(
        "nested.rego",
        "package nested\n\ninclude if input.item.attrs.price.value < 10\n",
    )
    for target, dialect in [("sql", "postgresql"), ("ucast", "all")]:
        with pytest.raises(OpaError) as exc:
            engine.compile_filters(
                "data.nested.include",
                unknowns=["input.item"],
                target=target,
                dialect=dialect,
            )
        assert exc.value.code == "compile_error"
        assert "invalid ref operand" in exc.value.message


def test_compile_filters_ref_shape_is_input_table_column(engine):
    # The two segments are counted from input, not from the unknown: the bare
    # unknown "input" admits input.<table>.<column>, while a narrower unknown
    # only admits one further segment.
    engine.add_policy(
        "shape.rego",
        """
        package shape

        two if input.attrs.name == "x"
        three if input.item.attrs.name == "x"
        """,
    )
    result = engine.compile_filters(
        "data.shape.two", unknowns=["input"], target="ucast", dialect="all"
    )
    assert result["query"] == {
        "type": "field",
        "field": "attrs.name",
        "operator": "eq",
        "value": "x",
    }
    with pytest.raises(OpaError) as exc:
        engine.compile_filters(
            "data.shape.three",
            unknowns=["input.item"],
            target="ucast",
            dialect="all",
        )
    assert "invalid ref operand" in exc.value.message


def test_compile_filters_eav_known_types_unknown_values(engine):
    # EAV split across two tables: attrs_types (attribute key -> datatype) is
    # known metadata, attrs_values (one column per attribute key) is the
    # unknown. Partial evaluation iterates the known types table and expands
    # it into concrete per-column conditions on the unknown values table.
    engine.add_policy(
        "eav2.rego",
        """
        package eav2

        include if {
            some key, type in data.attrs_types
            type == "number"
            input.attrs_values[key] < 10
        }

        include if {
            some key, type in data.attrs_types
            type == "string"
            input.attrs_values[key] == "Banane"
        }
        """,
    )
    engine.add_data(
        {"price": "number", "qty": "number", "name": "string", "organic": "bool"},
        path="attrs_types",
    )

    result = engine.compile_filters(
        "data.eav2.include",
        unknowns=["input.attrs_values"],
        target="sql",
        dialect="postgresql",
    )
    clauses = result["query"].removeprefix("WHERE (").removesuffix(")").split(" OR ")
    assert sorted(clauses) == [
        "attrs_values.name = E'Banane'",
        "attrs_values.price < E'10'",
        "attrs_values.qty < E'10'",
    ]  # no condition for "organic": no rule covers datatype "bool"

    result = engine.compile_filters(
        "data.eav2.include",
        unknowns=["input.attrs_values"],
        target="ucast",
        dialect="all",
    )
    top = result["query"]
    assert top["type"] == "compound" and top["operator"] == "or"
    assert sorted(
        (c["field"], c["operator"], c["value"]) for c in top["value"]
    ) == [
        ("attrs_values.name", "eq", "Banane"),
        ("attrs_values.price", "lt", 10),
        ("attrs_values.qty", "lt", 10),
    ]


def test_compile_filters_eav_known_types_from_input(engine):
    # The known types table can also arrive as (known) input alongside the
    # unknown values table under the same input document.
    engine.add_policy(
        "eav3.rego",
        """
        package eav3

        include if {
            some key, type in input.attrs_types
            type == "number"
            input.attrs_values[key] < 10
        }
        """,
    )
    result = engine.compile_filters(
        "data.eav3.include",
        {"attrs_types": {"price": "number", "name": "string"}},
        unknowns=["input.attrs_values"],
        target="sql",
        dialect="postgresql",
    )
    assert result["query"] == "WHERE attrs_values.price < E'10'"
