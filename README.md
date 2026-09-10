# opa-golib-python-bindings

Python bindings for the [OPA](https://www.openpolicyagent.org/) Rego engine, embedding
`github.com/open-policy-agent/opa/v1/rego` via a Go c-shared library and a stdlib-only
ctypes wrapper.

## Build

Requires Go >= 1.26 and Python >= 3.14.

```sh
make build   # builds src/opa_bindings/libopabridge.so
make test    # builds + runs pytest
```

## Usage

```python
from opa_bindings import OpaEngine

users = {"alice": {"role": "admin"}}

with OpaEngine() as engine:
    engine.add_policy("authz.rego", """
package authz

allow if lookup_user(input.user).role == "admin"
""")
    engine.add_data({"admin": ["alice"]}, path="roles")   # deep-merged; conflicts raise
    engine.register_function("lookup_user", lambda name: users.get(name))

    engine.eval_document("authz.allow", {"user": "alice"})  # -> True
    engine.eval_query("x = data.roles.admin[_]")            # -> [{"x": "alice"}]
```

Notes:

- `add_data` deep-merges objects; identical values coexist, conflicting values raise
  `OpaError(code="merge_conflict")` naming the conflicting path.
- A Go-side panic in any bridge call surfaces as `OpaError(code="panic")`
  instead of killing the process; the engine stays usable afterwards. (The
  bridge also validates `compile_filters(mappings=...)` values are strings
  and rejects malformed shapes with `OpaError(code="invalid_json")`.)
- `register_function` infers arity from the callable's signature. A `*args` function is
  variadic and is called from Rego with a single array argument: `many(["a", "b"])`
  (OPA does not support variadic builtins with return values).
- Builtin arguments and return values are JSON-compatible objects. A callback exception
  becomes an evaluation error; returning is fine.
- An undefined document raises `OpaUndefinedError`.
- Pass `coverage=True` to `eval_document` / `eval_query` to capture a coverage
  report (OPA's `cover` tracer) in `engine.last_coverage`: per-file `covered` /
  `not_covered` line ranges plus line counts and a coverage percentage over all
  added policies. Evaluating without `coverage=True` resets it to `None`.
- Pass `trace=True` to capture the full evaluation trace in `engine.last_trace`:
  a list of event dicts (`op`, `location`, `node`, `locals`, ...) in evaluation
  order. `locals` holds the plugged variable bindings live at each step, so the
  value a statement produced is visible (e.g. `{"x": 6}` after `x := input.n * 2`);
  a false condition appears as a `Fail` event at its location. An undefined
  document still carries its trace — the main way to see which condition failed. Note that `node`
  shows the compiler-rewritten expression (temporaries like `__local0__`), a
  statement may appear multiple times (`Redo` on backtracking), and tracing
  slows evaluation, so keep it opt-in per call. Coverage only records *which*
  statements were evaluated; traces are how to see their results.
- `compile_filters` partially evaluates a query and translates the residual
  policy into a data filter (OPA's Compile-API / data-filter machinery):

  ```python
  engine.add_policy("filters.rego", """
  package filters

  include if input.fruits.colour == "green"
  include if {
      input.fruits.name == "banana"
      input.user == "admin"
  }
  """)
  engine.compile_filters(
      "data.filters.include",
      {"user": "admin"},              # known input
      unknowns=["input.fruits"],      # left symbolic
      target="sql", dialect="postgresql",
  )
  # -> {"query": "WHERE (fruits.colour = E'green' OR fruits.name = E'banana')",
  #     "masks": None}
  ```

  `target="sql"` (dialects `postgresql`, `mysql`, `sqlserver`, `sqlite`)
  yields a WHERE clause string; `target="ucast"` (dialects `all`, `prisma`,
  `linq`, or `""`) yields a UCAST condition dict (the `ucast.json` wire
  format). `query` is `None` when the policy can never match and `""`/`{}`
  when it always matches. `mappings` renames tables/columns (e.g.
  `{"fruits": {"$self": "fruit_table", "colour": "col"}}`), and `mask_rule`
  names a rule evaluated to produce column masks (returned under `"masks"`).
  Residual conditions that cannot be expressed for the chosen target raise
  `OpaError(code="compile_error")`.

  Unknown refs must have the shape `input.<table>.<column>` — exactly two
  segments after `input`, whatever the declared unknown boundary is, and for
  every target/dialect (`ucast`/`all` included; `mappings` cannot deepen it).
  So `unknowns=["input.item"]` permits only `input.item.<column>`, while the
  bare `unknowns=["input"]` permits `input.<table>.<column>`. Deeper refs
  like `input.item.attrs.price.value` fail with `pe_fragment_error: invalid
  ref operand`, so nested documents (e.g. an EAV entity with per-attribute
  type/value objects, or per-locale value objects) must be flattened into
  columns (`input.attr.value_number`, `input.attr.value_de`, ...). Dynamic
  column choice is fine as long as the key is known at compile time:
  `input.attr[sprintf("value_%s", [input.locale])]` resolves to a single
  column during partial evaluation.
- Rego `print(...)` output is captured per evaluation: set `engine.print_handler`
  to a `callable(message, location)` to receive it (default: written to stderr);
  `engine.last_prints` holds the `(message, location)` pairs of the last eval.
- **Concurrency:** an engine may be shared across threads — evals are
  serialized by an internal re-entrant lock (builtins may evaluate on their
  own engine). Per-eval state (`last_trace`, `last_coverage`, `last_prints`)
  reflects the most recently *completed* eval, so with a shared engine prefer
  return values over `last_*` attributes, or use one engine per thread.
- **Resource limits / DoS:** there are no built-in caps. Policy/data sizes,
  the number of engines (call `close()`; `__del__` is best-effort under GC),
  and the set of distinct query strings (each is cached as a prepared query
  on the engine, invalidated by any config change) are bounded only by the
  process. If queries are dynamic or attacker-shaped, cap and canonicalize
  them in the application; treat `query`, `policy source`, and `data` as
  privileged inputs on a multi-tenant host. Rego itself can loop/compute
  without limits, so the caller should apply timeouts/load controls at the
  application layer if policies are untrusted.
- **Confidentiality:** traces (`trace=True`) capture the plugged values of
  local variables, and Rego `print()` calls see their arguments; both can
  contain secrets from `input` or `data`. Keep them off shared logs, or
  scrub them, when evaluating sensitive inputs. (The default print handler
  writes to stderr.)
