"""Tests backing opa_ucast_django_handoff.md.

That document designs a Django ORM compiler that consumes OPA's UCAST
output for a recursive/cyclic EAV + relation graph: quantifiers, aliasing,
and graph traversal are encoded as synthetic strings inside field names
(e.g. ``"$root/$some:member/$bind"``, ``"m1/active"``) under a single
unknown ``input.attrs`` document, because OPA itself only ever sees a flat
key-value table and has no notion of the graph.

These tests do not implement the Django compiler (out of scope here); they
prove the OPA half of the handoff: that partially evaluating a policy
written in that synthetic-field-name style, with ``input.attrs`` unknown,
produces UCAST/SQL residuals with the exact shape the Django compiler is
designed to parse -- literal field names carrying the special characters
intact, known values substituted in, and the source policy's and/or/not
Boolean structure preserved across predicates that reference different
scopes (the handoff's top-priority, previously-broken case).
"""

import pytest

from opa_bindings import OpaEngine, OpaError


@pytest.fixture
def engine():
    with OpaEngine() as e:
        yield e

# Mirrors the handoff doc's worked example: a correlated existential over
# "member" followed by a nested universal over "project", using the
# "$root/$some:<relation>/$bind" / "<alias>/<attribute>" grammar. Rego (and
# OPA's compile API) has no idea any of this means "graph traversal" -- to
# OPA these are just string-valued keys under input.attrs.
NESTED_QUANTIFIERS = """
package authz

allow if {
    input.user.enabled == true

    input.attrs["$root/$some:member/$bind"] == "m1"

    input.attrs["m1/active"] == true
    input.attrs["m1/department"] == input.user.department

    input.attrs["m1/$all:project/$bind"] == "p1"
    input.attrs["p1/classification"] <= input.user.clearance
}
"""


def test_nested_quantifiers_become_flat_field_predicates(engine):
    # OPA is agnostic to the quantifier/relation grammar embedded in the key
    # strings: it just emits one "field == value" (or "<=") predicate per
    # attrs[...] comparison, with the known input.user.* values substituted
    # in. This is exactly the flat structure the Django-side compiler's
    # synthetic-field-name parser expects to receive.
    engine.add_policy("authz.rego", NESTED_QUANTIFIERS)
    result = engine.compile_filters(
        "data.authz.allow",
        {"user": {"enabled": True, "department": "Sales", "clearance": 3}},
        unknowns=["input.attrs"],
        target="ucast",
        dialect="all",
    )
    assert result["masks"] is None
    assert result["query"] == {
        "type": "compound",
        "operator": "and",
        "value": [
            {
                "type": "field",
                "field": "attrs.$root/$some:member/$bind",
                "operator": "eq",
                "value": "m1",
            },
            {
                "type": "field",
                "field": "attrs.m1/active",
                "operator": "eq",
                "value": True,
            },
            {
                "type": "field",
                "field": "attrs.m1/department",
                "operator": "eq",
                "value": "Sales",
            },
            {
                "type": "field",
                "field": "attrs.m1/$all:project/$bind",
                "operator": "eq",
                "value": "p1",
            },
            {
                "type": "field",
                "field": "attrs.p1/classification",
                "operator": "lte",
                "value": 3,
            },
        ],
    }


def test_nested_quantifiers_become_flat_field_predicates_sql(engine):
    # Same policy, SQL target: the synthetic names survive as quoted
    # identifiers, so the same policy can drive either compiler backend.
    engine.add_policy("authz.rego", NESTED_QUANTIFIERS)
    result = engine.compile_filters(
        "data.authz.allow",
        {"user": {"enabled": True, "department": "Sales", "clearance": 3}},
        unknowns=["input.attrs"],
        target="sql",
        dialect="postgresql",
    )
    assert result["query"] == (
        'WHERE (attrs."$root/$some:member/$bind" = E\'m1\''
        ' AND attrs."m1/active" = TRUE'
        ' AND attrs."m1/department" = E\'Sales\''
        ' AND attrs."m1/$all:project/$bind" = E\'p1\''
        " AND attrs.\"p1/classification\" <= E'3')"
    )


# Handoff doc, "Required Django Integration Tests" #10 -- the case that broke
# the first prototype: a Boolean subtree referencing two different scopes
# ($root and the m1 binding) at once. In idiomatic Rego, "OR" is expressed as
# multiple rule bodies, so the correlating $bind predicate is repeated in
# each body; partial evaluation must still merge them into a single
# "or of and" residual rather than losing the shared $bind condition.
CROSS_SCOPE_OR = """
package authz

allow if {
    input.attrs["$root/$some:member/$bind"] == "m1"
    input.attrs["$root/category"] == "public"
}

allow if {
    input.attrs["$root/$some:member/$bind"] == "m1"
    input.attrs["m1/active"] == true
}
"""


def test_cross_scope_or_preserves_boolean_structure(engine):
    engine.add_policy("authz.rego", CROSS_SCOPE_OR)
    result = engine.compile_filters(
        "data.authz.allow", unknowns=["input.attrs"], target="ucast", dialect="all"
    )
    bind_m1 = {
        "type": "field",
        "field": "attrs.$root/$some:member/$bind",
        "operator": "eq",
        "value": "m1",
    }
    category_public = {
        "type": "field",
        "field": "attrs.$root/category",
        "operator": "eq",
        "value": "public",
    }
    m1_active = {
        "type": "field",
        "field": "attrs.m1/active",
        "operator": "eq",
        "value": True,
    }
    branch_a = {"type": "compound", "operator": "and", "value": [bind_m1, category_public]}
    branch_b = {"type": "compound", "operator": "and", "value": [bind_m1, m1_active]}
    # Rule evaluation order is not guaranteed.
    assert result["query"] in (
        {"type": "compound", "operator": "or", "value": [branch_a, branch_b]},
        {"type": "compound", "operator": "or", "value": [branch_b, branch_a]},
    )


# Handoff doc #9: NONE (negated existential) -- "not exists m1 with banned".
NEGATED_EXISTENTIAL = """
package authz

allow if {
    input.attrs["$root/$none:member/$bind"] == "m1"
    not input.attrs["m1/banned"] == true
}
"""


def test_negated_existential_becomes_not_compound(engine):
    # "not" over an unknown-attrs comparison is translated to a UCAST "not"
    # compound wrapping the field predicate, rather than being rejected or
    # silently dropped -- the Django compiler's normalization of "$none" into
    # NOT EXISTS(...) can rely on this shape being present verbatim.
    engine.add_policy("authz.rego", NEGATED_EXISTENTIAL)
    result = engine.compile_filters(
        "data.authz.allow", unknowns=["input.attrs"], target="ucast", dialect="all"
    )
    assert result["query"] == {
        "type": "compound",
        "operator": "and",
        "value": [
            {
                "type": "field",
                "field": "attrs.$root/$none:member/$bind",
                "operator": "eq",
                "value": "m1",
            },
            {
                "type": "compound",
                "operator": "not",
                "value": [
                    {
                        "type": "field",
                        "field": "attrs.m1/banned",
                        "operator": "eq",
                        "value": True,
                    }
                ],
            },
        ],
    }


def test_synthetic_field_names_survive_mappings_rename(engine):
    # The handoff's grammar lives entirely inside the field *name* under a
    # single unknown table (input.attrs); renaming that table via mappings
    # (e.g. to the real EAV table name) must not touch the synthetic suffix.
    engine.add_policy(
        "authz.rego",
        """
        package authz

        allow if {
            input.attrs["$root/$some:member/$bind"] == "m1"
            input.attrs["m1/active"] == true
        }
        """,
    )
    result = engine.compile_filters(
        "data.authz.allow",
        unknowns=["input.attrs"],
        target="ucast",
        dialect="all",
        mappings={"attrs": {"$self": "entity_attr"}},
    )
    assert result["query"] == {
        "type": "compound",
        "operator": "and",
        "value": [
            {
                "type": "field",
                "field": "entity_attr.$root/$some:member/$bind",
                "operator": "eq",
                "value": "m1",
            },
            {
                "type": "field",
                "field": "entity_attr.m1/active",
                "operator": "eq",
                "value": True,
            },
        ],
    }


def test_unresolvable_policy_still_raises_compile_error(engine):
    # A sanity check that this style of policy does not somehow bypass the
    # translator's normal error handling: a comparison OPA cannot express as
    # a filter (regex over the unknown) still raises compile_error, so the
    # Django compiler can trust that anything it receives is well-formed.
    engine.add_policy(
        "authz.rego",
        'package authz\n\nallow if regex.match("^a", input.attrs["m1/active"])\n',
    )
    with pytest.raises(OpaError) as exc:
        engine.compile_filters(
            "data.authz.allow", unknowns=["input.attrs"], target="ucast", dialect="all"
        )
    assert exc.value.code == "compile_error"
