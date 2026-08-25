"""High-level Python API around the Go/OPA bridge library."""

import ctypes
import inspect
import json
import sys

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


def _get_lib():
    global _lib
    if _lib is None:
        _lib = _native.load()
    return _lib


class OpaEngine:
    """An embedded OPA policy engine instance.

    Policies are Rego modules added under a path, data is deep-merged JSON,
    and Python callables can be registered as custom Rego builtins.
    """

    def __init__(self):
        self._lib = _get_lib()
        self._handle = self._lib.OpaNew()
        self._functions = {}
        # Buffers returned to Go must outlive the call; Go copies them
        # synchronously, so keeping the latest buffer per builtin suffices.
        self._callback_buffers = {}
        self._trampoline = _native.CALLBACK(self._dispatch)
        #: Called as ``print_handler(message, location)`` for each Rego
        #: ``print(...)`` during evaluation; None writes them to stderr.
        self.print_handler = None
        #: Prints captured by the most recent eval, as (message, location).
        self.last_prints = []

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

    def _eval_result(self, envelope):
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
            buf = ctypes.create_string_buffer(json.dumps(response).encode())
        except Exception as e:
            buf = ctypes.create_string_buffer(
                json.dumps({"error": f"unserializable result: {e!r}"}).encode()
            )
        self._callback_buffers[name] = buf
        return ctypes.addressof(buf)

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

    def eval_query(self, query: str, input=None):
        """Evaluate a Rego query; returns a list of binding dicts."""
        self._check_open()
        rs = self._eval_result(
            self._call(self._lib.OpaEvalQuery, query.encode(), _encode_input(input))
        )
        if not rs:
            return []
        return [r.get("bindings", {}) for r in rs]

    def eval_document(self, path: str, input=None):
        """Evaluate the document at ``data.<path>`` and return its value.

        Raises OpaUndefinedError if the document is undefined.
        """
        self._check_open()
        rs = self._eval_result(
            self._call(self._lib.OpaEvalDocument, path.encode(), _encode_input(input))
        )
        if not rs or not rs[0].get("expressions"):
            raise OpaUndefinedError(f"data.{path}" if path else "data")
        return rs[0]["expressions"][0]["value"]


def _encode_input(input):
    if input is None:
        return b""
    return json.dumps(input).encode()
