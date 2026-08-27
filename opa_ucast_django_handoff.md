# Handoff: OPA UCAST → Django ORM Compiler for Recursive EAV Graphs

## Objective

Build a robust compiler that takes **Open Policy Agent UCAST output** from partial evaluation and translates it into **Django ORM expressions** over a recursive/cyclic **EAV + relation graph**.

The design must support:

- EAV attributes
- graph relations between entities
- recursive/cyclic data
- existential quantification (`some`)
- universal quantification (`all`)
- negated existential quantification (`none`)
- nested quantifiers
- correct alias correlation
- Django ORM only
- no handwritten SQL required for the normal path
- preservation of OPA/UCAST Boolean structure (`and`, `or`, `not`)
- correct handling of empty relations and missing attributes

The current prototype mostly works but has one important limitation around **Boolean expressions that reference multiple scopes at once**.

---

# Conceptual Architecture

```text
Rego policy
    ↓
OPA partial evaluation
    ↓
UCAST
    ↓
Parse synthetic field names
    ↓
Binding-aware relational AST
    ↓
Normalize quantifiers
    ↓
Django Q / Exists / OuterRef / Subquery expressions
    ↓
QuerySet
```

OPA is responsible for policy logic, partial evaluation, substitution of known input values, and producing filter conditions. The Django side is responsible for EAV lookup semantics, graph traversal, quantifier bindings, alias identity/correlation, cyclic graph semantics, and ORM query construction.

---

# Why Synthetic Field Names Are Needed

OPA UCAST effectively treats the unknown document as a flat set of fields. To encode deeper graph semantics, traversal and quantification are placed **inside the UCAST field name string**.

Example:

```rego
input.attrs["$root/$some:member/$bind"] == "m1"
input.attrs["m1/active"] == true
input.attrs["m1/department"] == "Sales"
```

OPA sees these only as fields under `input.attrs`. The Django-side compiler interprets them as:

```text
EXISTS m1 IN root.member:
    m1.active == true
    AND
    m1.department == "Sales"
```

---

# Synthetic Field Grammar

Recommended syntax:

```text
$root/$some:<relation>/$bind
<alias>/$some:<relation>/$bind

$root/$all:<relation>/$bind
<alias>/$all:<relation>/$bind

$root/$none:<relation>/$bind
<alias>/$none:<relation>/$bind

<alias>/<attribute>
$root/<attribute>
```

Example:

```text
$root/$some:member/$bind = "m1"
m1/active = true
m1/department = "Sales"
```

Nested example:

```text
$root/$some:member/$bind = "m1"
m1/$all:project/$bind = "p1"
p1/enabled = true
```

Meaning:

```text
EXISTS m1 IN root.member:
    FOR ALL p1 IN m1.project:
        p1.enabled == true
```

---

# `$bind` Semantics

`$bind` introduces a **symbolic query variable**, not a database ID.

```text
$root/$some:member/$bind == "m1"
```

means:

```text
Bind symbolic alias m1
to an entity reached from root via relation "member"
under existential quantification.
```

`m1` is not an actual entity primary key. If persistent entity identity is needed later, use a separate concept such as `m1/$id`.

---

# Quantifier Semantics

## `$some`

```text
$root/$some:member/$bind = m1
m1/active = true
```

means:

```text
EXISTS m1 IN root.member:
    m1.active == true
```

Django shape:

```python
Exists(
    related_members.filter(
        ...
    )
)
```

## `$none`

```text
$root/$none:member/$bind = m1
m1/banned = true
```

means:

```text
NOT EXISTS m1 IN root.member:
    m1.banned == true
```

## `$all`

```text
$root/$all:member/$bind = m1
m1/active = true
```

means:

```text
FOR ALL m1 IN root.member:
    m1.active == true
```

Normalize to:

```text
NOT EXISTS m1 IN root.member:
    NOT (m1.active == true)
```

This is the preferred implementation because `Exists()` / `NOT Exists()` map naturally to Django.

### Vacuous truth

If `root.member` is empty, then:

```text
FOR ALL member:
    active == true
```

is `true`.

If non-empty universal semantics are desired, add a later extension such as `$all+` with:

```text
EXISTS member
AND
NOT EXISTS violating_member
```

---

# Recommended Quantifier Set

```text
$some:<relation>
$all:<relation>
$none:<relation>
```

Possible future extension:

```text
$all+:<relation>
```

---

# Example OPA Policy

```rego
package authz

default allow := false

allow if {
    input.user.enabled == true

    input.attrs["$root/$some:member/$bind"] == "m1"

    input.attrs["m1/active"] == true
    input.attrs["m1/department"] == input.user.department

    input.attrs["m1/$all:project/$bind"] == "p1"
    input.attrs["p1/classification"] <= input.user.clearance
}
```

Known input:

```json
{
  "user": {
    "enabled": true,
    "department": "Sales",
    "clearance": 3
  }
}
```

Treat `input.attrs` as unknown during OPA compile.

Residual semantics:

```text
$root/$some:member/$bind == "m1"
m1/active == true
m1/department == "Sales"

m1/$all:project/$bind == "p1"
p1/classification <= 3
```

---

# Example UCAST

```json
{
  "type": "compound",
  "operator": "and",
  "value": [
    {
      "type": "field",
      "field": "attrs.$root/$some:member/$bind",
      "operator": "eq",
      "value": "m1"
    },
    {
      "type": "field",
      "field": "attrs.m1/active",
      "operator": "eq",
      "value": true
    },
    {
      "type": "field",
      "field": "attrs.m1/department",
      "operator": "eq",
      "value": "Sales"
    },
    {
      "type": "field",
      "field": "attrs.m1/$all:project/$bind",
      "operator": "eq",
      "value": "p1"
    },
    {
      "type": "field",
      "field": "attrs.p1/classification",
      "operator": "lte",
      "value": 3
    }
  ]
}
```

---

# Suggested EAV + Graph Schema

```python
class Entity(models.Model):
    pass
```

Relations:

```python
class Edge(models.Model):
    source = models.ForeignKey(
        Entity,
        on_delete=models.CASCADE,
        related_name="outgoing_edges",
    )
    target = models.ForeignKey(
        Entity,
        on_delete=models.CASCADE,
        related_name="incoming_edges",
    )
    relation = models.CharField(max_length=255)
```

Attributes:

```python
class Attribute(models.Model):
    class Kind(models.TextChoices):
        TEXT = "text"
        NUMBER = "number"
        BOOL = "bool"
        NULL = "null"

    entity = models.ForeignKey(
        Entity,
        on_delete=models.CASCADE,
        related_name="attributes",
    )

    key = models.CharField(max_length=255)
    kind = models.CharField(max_length=16, choices=Kind.choices)

    text_value = models.TextField(null=True)
    number_value = models.DecimalField(
        max_digits=38,
        decimal_places=10,
        null=True,
    )
    bool_value = models.BooleanField(null=True)
```

The value storage can be adapted to `JSONField` if needed.

---

# Intermediate AST

Do not compile UCAST directly to `Q()` everywhere. Use an intermediate relational AST.

```python
@dataclass(frozen=True)
class Const:
    value: bool


@dataclass(frozen=True)
class AttributePredicate:
    alias: str
    key: str
    operator: str
    value: Any


@dataclass(frozen=True)
class And:
    children: tuple["Expr", ...]


@dataclass(frozen=True)
class Or:
    children: tuple["Expr", ...]


@dataclass(frozen=True)
class Not:
    child: "Expr"


@dataclass(frozen=True)
class Quantifier:
    quantifier: Literal["some", "all", "none"]
    alias: str
    relation: str
    body: "Expr"
```

However, this AST needs one refinement described below.

---

# Critical Compiler Requirement: Preserve Cross-Scope Boolean Expressions

The first prototype assigned every Boolean subtree to exactly one alias. That is too restrictive.

This valid expression breaks the current prototype:

```text
EXISTS m1 IN root.member:
    root.category == "public"
    OR
    m1.active == true
```

Encoded as UCAST:

```json
{
  "type": "compound",
  "operator": "and",
  "value": [
    {
      "type": "field",
      "field": "attrs.$root/$some:member/$bind",
      "operator": "eq",
      "value": "m1"
    },
    {
      "type": "compound",
      "operator": "or",
      "value": [
        {
          "type": "field",
          "field": "attrs.$root/category",
          "operator": "eq",
          "value": "public"
        },
        {
          "type": "field",
          "field": "attrs.m1/active",
          "operator": "eq",
          "value": true
        }
      ]
    }
  ]
}
```

The old prototype rejects this because the OR subtree references `$root` and `m1` at once.

The next version must support it.

---

# Recommended AST Improvement

Instead of assuming every predicate belongs to the current alias, make the entity reference explicit:

```python
@dataclass(frozen=True)
class EntityRef:
    name: str


@dataclass(frozen=True)
class AttributePredicate:
    entity: EntityRef
    key: str
    operator: str
    value: Any
```

Then:

```text
root.category == "public"
OR
m1.active == true
```

becomes:

```python
Or(
    (
        AttributePredicate(
            entity=EntityRef("$root"),
            key="category",
            operator="eq",
            value="public",
        ),
        AttributePredicate(
            entity=EntityRef("m1"),
            key="active",
            operator="eq",
            value=True,
        ),
    )
)
```

---

# Binding Environment

The Django compiler should use an explicit scope/binding environment.

Conceptually:

```python
compile_expr(
    expr,
    bindings={
        "$root": RootBinding(...),
        "m1": CurrentSubqueryBinding(...),
        "p1": CurrentSubqueryBinding(...),
    },
)
```

A field reference must resolve through the binding environment rather than always using the current `OuterRef("pk")`.

This is necessary for root references inside child scopes, ancestor references, field-to-field comparisons, future cycle closure, and nested quantifiers.

---

# Django ORM Translation

## Attribute predicate

Conceptually:

```text
m1/active == true
```

becomes:

```python
Exists(
    Attribute.objects.filter(
        entity_id=<resolved m1 entity>,
        key="active",
        kind="bool",
        bool_value=True,
    )
)
```

## `$some`

```text
EXISTS child WHERE P(child)
```

becomes:

```python
Exists(
    related_entities.filter(
        compile_expr(P)
    )
)
```

## `$none`

```text
NOT EXISTS child WHERE P(child)
```

becomes:

```python
~Exists(
    related_entities.filter(
        compile_expr(P)
    )
)
```

## `$all`

Normalize:

```text
FOR ALL child:
    P(child)
```

into:

```text
NOT EXISTS child:
    NOT P(child)
```

Then Django:

```python
~Exists(
    related_entities.filter(
        NOT compile_expr(P)
    )
)
```

---

# Important Missing-Attribute Semantics

For:

```text
m1/active == true
```

if `active` is absent, the predicate should be false.

Therefore:

```text
ALL member:
    member.active == true
```

must fail if any member has no `active` attribute.

Be careful with `ne`.

Example:

```text
m1/foo != "bar"
```

Choose one of these semantics explicitly:

1. Missing attribute means false
2. Missing attribute means true
3. Three-valued/undefined semantics

The prototype used:

```text
missing attribute → predicate false
```

---

# Tested Cases

A pure-Python graph evaluator was used to test parser/lowering semantics. Django was not installed in the execution environment, so ORM SQL generation itself was not executed.

The following passed:

| Case | Result |
|---|---|
| Correlated `$some` with multiple predicates | Pass |
| `$all` with multiple predicates | Pass |
| Nested `$all` → `$all` | Pass |
| Nested `$all` → `$some` | Pass |
| Vacuous truth for empty `$all` relation | Pass |
| `$some` on empty relation | Pass |
| Missing attribute under `$all` | Pass |
| `$none` | Pass |
| Nested `$all` → `$none` | Pass |
| Reusing alias name in independent OR branches | Pass |
| Duplicate alias in same scope | Correctly rejected |
| Unbound alias | Correctly rejected |
| Cyclic symbolic binding graph | Correctly rejected |

Unsupported/failing case:

```text
Boolean subtree references multiple aliases/scopes
```

Example:

```text
root.category == "public"
OR
m1.active == true
```

This must be implemented in the next revision.

---

# Alias Scoping

Aliases must be lexical, not global.

Example:

```text
OR
├── AND
│   ├── bind member AS m1
│   └── m1.department == Sales
│
└── AND
    ├── bind member AS m1
    └── m1.department == Engineering
```

These are two independent `m1` bindings.

Do not globally merge aliases merely because the strings are identical.

Compiler recursion should carry a scope object:

```python
compile(node, scope)
```

---

# Cycles

The database graph may be cyclic. That is not a problem by itself because query depth is determined by the policy, not by recursively walking the graph in Python.

Example data:

```text
Alice --manager--> Bob
Bob   --manager--> Carol
Carol --manager--> Alice
```

A finite policy such as:

```text
$root/$some:manager/$bind = m1
m1/$some:manager/$bind = m2
```

still produces finite ORM nesting.

---

# Future Cycle Closure / Identity References

A future requirement is to support true graph-cycle constraints such as:

```text
m1 -> manager -> m2
m2 -> subordinate -> m1
```

For that, add explicit entity identity/reference semantics.

Possible syntax:

```text
m1/$id
m2/$edge:subordinate/$target
```

or field-to-field comparison.

Future AST should support something like:

```python
@dataclass(frozen=True)
class FieldRef:
    entity: EntityRef
    key: str
```

Do not conflate `$bind` with actual database identity.

---

# Recursive / Transitive Traversal

Do not model unbounded recursion by blindly repeating `$some`.

If needed later, add explicit traversal syntax such as:

```text
$reach:<relation>:<min-depth>:<max-depth>
```

Example:

```text
$root/$reach:manager:1:8/$bind = m1
```

Possible implementations:

- recursive CTE
- closure table
- materialized path
- precomputed transitive closure

For authorization-heavy workloads, a closure table may be preferable.

---

# URL Escaping / Field-Name Escaping

Because `/`, `:`, `$`, and other characters are structural, actual relation names and attribute keys should be escaped.

Recommended approach:

```text
percent-encoding
```

Then decode with:

```python
urllib.parse.unquote(...)
```

Do not allow unescaped structural delimiters in relation/attribute names.

---

# Operators

The initial compiler covered:

```text
eq
ne
lt
lte
gt
gte
in
nin
contains
startswith
endswith
```

Map these to typed EAV comparisons. For numeric comparison, avoid lexical text comparison. Typed attribute storage is strongly preferred.

---

# Suggested Next Implementation Steps

1. Refactor the relational AST so every field predicate carries an explicit `EntityRef`.
2. Preserve UCAST Boolean structure exactly.
3. Build lexical binding scopes.
4. Compile child/ancestor/root references through a binding environment.
5. Keep quantifiers as first-class AST nodes.
6. Normalize `all` → `NOT EXISTS violation` and `none` → `NOT EXISTS match`.
7. Compile to Django conditional expressions (`Q`, `Exists`, negation, etc.).
8. Add field-to-field comparison support.
9. Add cycle-closing entity identity support.
10. Add an actual Django test project using SQLite first, then PostgreSQL.
11. Assert resulting entity IDs, not just generated SQL strings.
12. Add SQL-count/performance tests for nested quantifiers.

---

# Required Django Integration Tests

## 1. Correlated existential

Data:

```text
root
├─ member → Alice
│           active=true
│           department=Sales
└─ member → Bob
            active=false
            department=Engineering
```

Policy:

```text
SOME member:
    active == true
    AND department == Sales
```

Expected: `root matches`.

## 2. Correlation must use the same entity

Data:

```text
root
├─ member → Alice
│           active=true
│           department=Engineering
└─ member → Bob
            active=false
            department=Sales
```

Policy:

```text
SOME member:
    active == true
    AND department == Sales
```

Expected: `root does NOT match`.

This is a critical test.

## 3. Universal success

```text
ALL member:
    active == true
```

All members active → match.

## 4. Universal violation

One inactive member → no match.

## 5. Vacuous universal

No members:

```text
ALL member:
    active == true
```

Expected: match.

## 6. Missing attribute under universal

One member lacks `active`.

Expected: no match.

## 7. Nested all/some

```text
ALL member:
    SOME project:
        enabled == true
```

Test:

- all members have at least one enabled project
- one member has only disabled projects
- one member has no projects

## 8. Nested all/all

```text
ALL member:
    ALL project:
        enabled == true
```

Verify vacuous truth for members with zero projects.

## 9. None

```text
NONE member:
    banned == true
```

## 10. Cross-scope OR

Must work:

```text
SOME member:
    root.category == "public"
    OR
    member.active == true
```

This currently fails in the prototype and is the highest-priority semantic fix.

## 11. Independent alias reuse in OR branches

```text
(
    SOME m1:
        m1.department == Sales
)
OR
(
    SOME m1:
        m1.department == Engineering
)
```

The two `m1` variables are independent.

## 12. Cyclic database data

```text
A -> B -> C -> A
```

Use finite policy depth. Compiler must terminate and generate finite ORM expressions.

## 13. Symbolic binding cycle

Invalid encoding:

```text
m2/$some:member/$bind = m1
m1/$some:member/$bind = m2
```

Must be rejected.

## 14. Duplicate binding alias in same lexical scope

Must be rejected.

## 15. Unbound alias

```text
ghost/active == true
```

Must be rejected.

---

# Performance Requirements

Avoid N+1 execution.

OPA should not call back into Django once per entity or attribute.

The final result should be a single QuerySet whenever practical.

Prefer:

- `Exists`
- `OuterRef`
- `Subquery`
- joins
- indexed attribute lookups

Do not materialize all entities in Python and then run policies individually.

---

# Security Requirements

Treat synthetic field strings as an input language.

Do not directly concatenate them into raw SQL or arbitrary Django lookup names.

Validate:

- quantifier name
- alias syntax
- relation name
- attribute name
- supported operators
- path shape
- escaping

Use a whitelist of operations. Reject malformed or unsupported structures explicitly.

---

# Main Design Principle

OPA decides:

```text
WHAT conditions must hold.
```

The Django compiler decides:

```text
HOW entities satisfying those conditions are retrieved.
```

Do not make OPA perform ORM/database lookups directly.

---

# Current Status

The design is viable.

The initial parser/lowering implementation successfully handled:

- nested quantifiers
- `all` / `some` / `none`
- missing values
- vacuous truth
- alias correlation
- alias reuse in separate branches
- symbolic binding cycle detection

The main remaining semantic problem is:

```text
Boolean expressions spanning multiple entity scopes.
```

Fix that by combining:

```text
preserving UCAST Boolean structure
+
explicit EntityRef on every predicate
+
lexical binding environment
```

After that, the next critical step is executing the compiler against a real Django model/database and verifying generated QuerySets for all cases above.
