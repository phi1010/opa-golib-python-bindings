"""High-level Python API around the Go/OPA bridge library."""

import ctypes
import inspect
import json
import sys
import threading

from . import _native


class OpaError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class OpaUndefinedError(OpaError):
    def __init__(self, what: str):
        super().__init__("undefined", f"{what} is undefined")


_lib = None
_libc = None


def _get_lib():
    global _lib
    if _lib is None:
        _lib = _native.load()
    return _lib


def _get_libc():
    """Handle for libc's malloc: callback response buffers are owned by the
    Go side, which frees them with the C allocator (see _dispatch)."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None)
        _libc.malloc.restype = ctypes.c_void_p
        _libc.malloc.argtypes = [ctypes.c_size_t]
    return _libc


class OpaEngine:
    """An embedded OPA policy engine instance.

    Policies are Rego modules added under a path, data is deep-merged JSON,
    and Python callables can be registered as custom Rego builtins.

    Concurrency and resource notes:

    - A single engine may be shared across threads: evaluations are
      serialized by an internal re-entrant lock (which also allows a builtin
      to evaluate on its own engine). Configuration calls (``add_policy``,
      ``add_data``, ``register_function``) may interleave with evals from
      other threads, as in the Go engine itself.
    - Per-eval state (``last_coverage``, ``last_trace``, ``last_prints``)
      reflects the most recently *completed* eval; under concurrent evals on
      a shared engine these may interleave. Use one engine per thread, or
      rely on return values instead of the ``last_*`` attributes, if that
      matters.
    - There are no built-in caps on memory or CPU: policy and data size,
      number of engines (call ``close()`` to release one), and the number of
      distinct queries evaluated are all bounded only by the process. Each
      distinct query string is kept in a prepared-query cache on the engine
      (invalidated by any configuration change), so applications that
      evaluate unbounded attacker-shaped query strings grow memory without
      bound — keep queries a fixed, application-controlled set.
    """

    def __init__(self):
        self._lib = _get_lib()
        self._libc = _get_libc()
        self._handle = self._lib.OpaNew()
        self._functions = {}
        # Serializes evals per engine so the per-eval callback buffer list
        # below stays consistent even when multiple threads share an engine
        # or a builtin re-enters eval on the same thread. A plain RLock: Go
        # callbacks for this engine's builtins run on the calling thread while
        # it holds the lock.
        self._eval_lock = threading.RLock()
        # Callback responses are malloc'd with the C allocator; Go frees them
        # with OpaFreeString after copying (ownership transfer), so Python
        # must NOT keep references. Buffers are only alive between _dispatch
        # and the matching OpaFreeString, which the eval lock makes safe.
        self._trampoline = _native.CALLBACK(self._dispatch)
        #: Called as ``print_handler(message, location)`` for each Rego
        #: ``print(...)`` during evaluation; None writes them to stderr.
        self.print_handler = None
        #: Prints captured by the most recent eval, as (message, location).
        self.last_prints = []
        #: Coverage report of the most recent eval with ``coverage=True``:
        #: {"files": {path: {"covered": [...], "not_covered": [...], ...}},
        #:  "covered_lines": int, "not_covered_lines": int, "coverage": float}.
        #: None if the last eval did not capture coverage.
        self.last_coverage = None
        #: Evaluation trace of the most recent eval with ``trace=True``: a
        #: list of event dicts {"op", "query_id", "parent_id", "location",
        #: "node", "locals", "message"} in evaluation order, where "locals"
        #: holds the variable bindings live at that point. None if the last
        #: eval did not capture a trace.
        self.last_trace = None

    # -- lifecycle -----------------------------------------------------

    def close(self):
        if self._handle is not None:
            self._lib.OpaDestroy(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # -- internals -----------------------------------------------------

    def _check_open(self):
        if self._handle is None:
            raise OpaError("closed", "engine has been closed")

    def _call(self, fn, *args):
        ptr = fn(self._handle, *args)
        if not ptr:
            raise OpaError("internal", "native call returned NULL")
        try:
            raw = ctypes.string_at(ptr)
        finally:
            self._lib.OpaFreeString(ptr)
        envelope = json.loads(raw)
        if "error" in envelope and envelope["error"] is not None:
            err = envelope["error"]
            raise OpaError(err.get("code", "unknown"), err.get("message", ""))
        return envelope

    def _eval_reset(self):
        # Clear per-eval state up front so a failed eval never leaves stale
        # results from a previous evaluation behind.
        self.last_coverage = None
        self.last_trace = None
        self.last_prints = []

    def _eval_result(self, envelope):
        self.last_coverage = envelope.get("coverage")
        self.last_trace = envelope.get("trace")
        self.last_prints = [
            (p["message"], p["location"]) for p in envelope.get("prints") or []
        ]
        for message, location in self.last_prints:
            if self.print_handler is not None:
                self.print_handler(message, location)
            else:
                print(f"{location}: {message}", file=sys.stderr)
        return envelope.get("result")

    def _dispatch(self, handle, name, args_json):
        name = name.decode()
        try:
            fn, arity = self._functions[name]
            args = json.loads(args_json)
            if arity == -1:
                # Variadic builtins take a single array argument in Rego.
                args = args[0]
            response = {"result": fn(*args)}
        except Exception as e:  # never let an exception cross into Go
            response = {"error": repr(e)}
        try:
            raw = json.dumps(response).encode()
        except Exception as e:
            raw = json.dumps({"error": f"unserializable result: {e!r}"}).encode()
        # malloc with the C allocator: ownership of this buffer transfers to
        # Go, which frees it with OpaFreeString (libc free) after copying.
        # Nothing on the Python side retains the pointer. It must not be
        # created with ctypes buffers — those use Python's allocator, which
        # is not compatible with libc free.
        buf = self._libc.malloc(len(raw) + 1)
        if not buf:
            return None  # Go reports "callback returned NULL"
        ctypes.memmove(buf, raw, len(raw))
        ctypes.memset(buf + len(raw), 0, 1)
        return buf

    # -- public API ----------------------------------------------------

    def add_policy(self, path: str, source: str):
        """Add a Rego module under the given path (module name)."""
        self._check_open()
        self._call(self._lib.OpaAddPolicy, path.encode(), source.encode())

    def add_data(self, value, path: str = ""):
        """Deep-merge a JSON-compatible value into the data document.

        ``path`` is a dotted path (e.g. ``"roles.admin"``); empty means root.
        Conflicting existing values raise OpaError(code="merge_conflict").
        """
        self._check_open()
        self._call(self._lib.OpaAddData, path.encode(), json.dumps(value).encode())

    def register_function(self, name: str, fn, *, arity: int | None = None):
        """Expose a Python callable as a Rego builtin.

        Arity is inferred from the signature unless given; ``*args`` means
        variadic, in which case the builtin takes a single array argument in
        Rego (e.g. ``many(["a", "b"])``) that is unpacked into ``*args``.
        Arguments and the return value are JSON-compatible objects.
        """
        self._check_open()
        if arity is None:
            arity = 0
            for p in inspect.signature(fn).parameters.values():
                if p.kind is inspect.Parameter.VAR_POSITIONAL:
                    arity = -1
                    break
                if p.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                ):
                    arity += 1
        self._functions[name] = (fn, arity)
        try:
            self._call(
                self._lib.OpaRegisterBuiltin, name.encode(), arity, self._trampoline
            )
        except Exception:
            del self._functions[name]
            raise

    def eval_query(
        self, query: str, input=None, *, coverage: bool = False, trace: bool = False
    ):
        """Evaluate a Rego query; returns a list of binding dicts.

        With ``coverage=True`` the evaluation is traced and a coverage report
        over all added policies is stored in ``self.last_coverage``. With
        ``trace=True`` the full event trace, including the variable bindings
        at each step, is stored in ``self.last_trace``.
        """
        self._check_open()
        with self._eval_lock:
            self._eval_reset()
            rs = self._eval_result(
                self._call(
                    self._lib.OpaEvalQuery,
                    query.encode(),
                    _encode_input(input),
                    int(coverage),
                    int(trace),
                )
            )
        if not rs:
            return []
        return [r.get("bindings", {}) for r in rs]

    def eval_document(
        self, path: str, input=None, *, coverage: bool = False, trace: bool = False
    ):
        """Evaluate the document at ``data.<path>`` and return its value.

        Raises OpaUndefinedError if the document is undefined. With
        ``coverage=True`` a coverage report is stored in ``self.last_coverage``;
        with ``trace=True`` the event trace is stored in ``self.last_trace``.
        """
        self._check_open()
        with self._eval_lock:
            self._eval_reset()
            rs = self._eval_result(
                self._call(
                    self._lib.OpaEvalDocument,
                    path.encode(),
                    _encode_input(input),
                    int(coverage),
                    int(trace),
                )
            )
        if not rs or not rs[0].get("expressions"):
            raise OpaUndefinedError(f"data.{path}" if path else "data")
        return rs[0]["expressions"][0]["value"]

    def compile_filters(
        self,
        query: str,
        input=None,
        *,
        unknowns=("input",),
        target: str = "sql",
        dialect: str = "postgresql",
        mappings=None,
        mask_rule: str | None = None,
    ):
        """Partially evaluate ``query`` and translate it into a data filter.

        Everything under the refs in ``unknowns`` (e.g. ``"input.fruits"``)
        is left unknown; the rest is evaluated using ``input`` and the data
        and policies already added. The residual conditions are translated
        for ``target``/``dialect``:

        - ``target="sql"`` with dialect ``postgresql``, ``mysql``,
          ``sqlserver`` or ``sqlite``: returns a SQL WHERE clause string.
        - ``target="ucast"`` with dialect ``all``, ``prisma``, ``linq`` or
          ``""``: returns a UCAST condition object (JSON-compatible dict).

        ``mappings`` optionally renames tables/columns (see the OPA docs on
        Compile API mappings); ``mask_rule`` names a rule (e.g.
        ``"data.filters.masks"``) evaluated to produce column masks.

        Returns ``{"query": <str or dict or None>, "masks": <dict or None>}``.
        A query of ``None`` means the policy can never be satisfied; an empty
        query means it is always satisfied. Raises OpaError with code
        ``compile_error`` if the residual policy cannot be expressed as a
        filter for the chosen target.

        Unknown refs are limited to ``input.<table>.<column>`` — exactly two
        segments after ``input``, for every target/dialect, wherever the
        declared unknown boundary sits (``mappings`` cannot deepen this):
        ``unknowns=["input.item"]`` permits only ``input.item.<column>``,
        the bare ``unknowns=["input"]`` permits ``input.<table>.<column>``.
        Nested documents like ``input.item.attrs.price.value`` are rejected
        and must be flattened into columns; a dynamic column picked from
        known values (``input.attr[sprintf("value_%s", [input.locale])]``)
        is fine, as it resolves during partial evaluation.
        """
        self._check_open()
        with self._eval_lock:
            envelope = self._call(
                self._lib.OpaCompileFilters,
                query.encode(),
                _encode_input(input),
                json.dumps(list(unknowns)).encode(),
                target.encode(),
                dialect.encode(),
                b"" if mappings is None else json.dumps(mappings).encode(),
                (mask_rule or "").encode(),
            )
        return envelope.get("result")


def _encode_input(input):
    if input is None:
        return b""
    return json.dumps(input).encode()
