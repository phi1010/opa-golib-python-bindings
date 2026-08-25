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
- `register_function` infers arity from the callable's signature. A `*args` function is
  variadic and is called from Rego with a single array argument: `many(["a", "b"])`
  (OPA does not support variadic builtins with return values).
- Builtin arguments and return values are JSON-compatible objects. A callback exception
  becomes an evaluation error; returning is fine.
- An undefined document raises `OpaUndefinedError`.
- Rego `print(...)` output is captured per evaluation: set `engine.print_handler`
  to a `callable(message, location)` to receive it (default: written to stderr);
  `engine.last_prints` holds the `(message, location)` pairs of the last eval.
