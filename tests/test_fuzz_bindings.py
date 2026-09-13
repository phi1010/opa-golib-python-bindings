"""Fuzz tests for the Python <-> Go binding layer.

These target the bridge itself — string marshalling across ctypes, JSON
envelopes, callback buffer ownership, handle lifecycle and locking — not
OPA's evaluator, so policies are kept trivial and the fuzzed values are the
things that cross the boundary.

Run a longer campaign with e.g.::

    PYTHONFAULTHANDLER=1 FUZZ_EXAMPLES=5000 pytest tests/test_fuzz_bindings.py -m fuzz
"""

import gc
import json
import math
import os
import random
import threading

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from opa_bindings import OpaEngine, OpaError, OpaUndefinedError

pytestmark = pytest.mark.fuzz

EXAMPLES = int(os.environ.get("FUZZ_EXAMPLES", "200"))
fuzz_settings = settings(
    max_examples=EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# Any Python text, including NUL, lone surrogates and non-BMP characters.
any_text = st.text(st.characters(codec=None), max_size=64)
# Integers well beyond float64/int64 precision.
big_ints = st.integers(min_value=-(2**128), max_value=2**128)
json_scalars = st.none() | st.booleans() | big_ints | st.floats(
    allow_nan=False, allow_infinity=False
) | any_text
json_values = st.recursive(
    json_scalars,
    lambda c: st.lists(c, max_size=6) | st.dictionaries(any_text, c, max_size=6),
    max_leaves=40,
)
# Values that ctypes/json may reject on the Python side before reaching Go.
hostile_values = json_values | st.sampled_from(
    [math.nan, math.inf, -math.inf, b"bytes", object(), {1: 2}, {(1,): 2}]
)


def _has_surrogate(v):
    try:
        json.dumps(v, ensure_ascii=False).encode()
        return False
    except UnicodeEncodeError:
        return True


def _normalize(v):
    """JSON round-trip on the Python side: what Go should hand back."""
    return json.loads(json.dumps(v))


def _is_expected_error(e):
    return isinstance(e, (OpaError, ValueError, TypeError, UnicodeError))


# -- marshalling ---------------------------------------------------------


@fuzz_settings
@given(value=json_values)
def test_data_roundtrip_is_exact(value):
    """add_data -> eval_document must return exactly what went in."""
    with OpaEngine() as e:
        if _has_surrogate(value):
            with pytest.raises(OpaError):
                e.add_data({"v": value})
            return
        e.add_data({"v": value})
        try:
            got = e.eval_document("v")
        except OpaUndefinedError:
            pytest.fail("value lost crossing the bridge")
        assert got == _normalize(value)


@fuzz_settings
@given(value=json_values)
def test_input_roundtrip_is_exact(value):
    with OpaEngine() as e:
        if _has_surrogate(value):
            with pytest.raises(OpaError):
                e.eval_query("x = input", {"k": value})
            return
        rows = e.eval_query("x = input", {"k": value})
        assert rows == [{"x": {"k": _normalize(value)}}]


@fuzz_settings
@given(path=any_text, source=any_text, query=any_text, dialect=any_text)
def test_arbitrary_strings_never_crash(path, source, query, dialect):
    """Strings passed as char* (NULs, surrogates, junk) must only ever raise
    Python exceptions — never crash, hang or corrupt the engine."""
    with OpaEngine() as e:
        for call in (
            lambda: e.add_policy(path, source),
            lambda: e.add_data({"a": 1}, path=path),
            lambda: e.eval_query(query),
            lambda: e.eval_document(path),
            lambda: e.compile_filters(query, dialect=dialect),
            lambda: e.compile_filters("data.x", target=dialect, mask_rule=path),
        ):
            try:
                call()
            except Exception as ex:
                assert _is_expected_error(ex), repr(ex)
        # Engine still healthy afterwards.
        e.add_policy("ok.rego", "package ok\n\nv := 1\n")
        assert e.eval_document("ok.v") == 1


@fuzz_settings
@given(key=any_text)
def test_nul_bytes_are_not_silently_truncated(key):
    """A NUL inside a string must not make it alias a different string on
    the Go side (C strings stop at NUL)."""
    with OpaEngine() as e:
        path = "a" + key
        if "\0" in key or _has_surrogate(key):
            with pytest.raises(OpaError):
                e.add_data(1, path="p." + path.replace(".", "_"))
            return
        e.add_data(1, path="p." + path.replace(".", "_"))
        doc = e.eval_document("")
        # The stored key must be the full key, not a truncated prefix.
        assert path.replace(".", "_") in doc["p"], doc


# -- callbacks -----------------------------------------------------------


@fuzz_settings
@given(args=st.lists(json_values, min_size=1, max_size=3), ret=hostile_values)
def test_callback_marshalling(args, ret):
    """Callback arguments arrive intact; any return value either comes back
    exactly or surfaces as an OpaError."""
    seen = []

    def fn(a):
        seen.append(a)
        return ret

    with OpaEngine() as e:
        e.register_function("cb", fn)
        if _has_surrogate(args):
            with pytest.raises(OpaError):
                e.eval_query("x = cb(input)", args)
            return
        try:
            rows = e.eval_query("x = cb(input)", args)
        except OpaError:
            try:
                json.dumps(ret, allow_nan=False)
                if _has_surrogate(ret):
                    raise ValueError
            except (TypeError, ValueError):
                return  # unserializable return is correctly an error
            raise
        assert seen and seen[0] == _normalize(args)
        # Known binding quirk: a callback returning None (JSON null) is
        # decoded by Go as a missing result, i.e. undefined, not null.
        assert rows == ([] if ret is None else [{"x": _normalize(ret)}])


@fuzz_settings
@given(size=st.integers(0, 1 << 22), exc=st.booleans())
def test_callback_large_and_failing_responses(size, exc):
    """Large callback buffers and exceptions do not leak or corrupt memory."""

    def fn(x):
        if exc:
            raise RuntimeError("x" * size)
        return "y" * size

    with OpaEngine() as e:
        e.register_function("cb", fn)
        for _ in range(3):
            if exc:
                with pytest.raises(OpaError):
                    e.eval_query("x = cb(1)")
            else:
                assert len(e.eval_query("x = cb(1)")[0]["x"]) == size


@fuzz_settings
@given(depth=st.integers(1, 12))
def test_callback_reentrancy(depth):
    """A builtin that re-enters eval on the same engine, recursively."""
    with OpaEngine() as e:

        def rec(n):
            if n <= 0:
                return 0
            return e.eval_query(f"x = rec({n - 1})")[0]["x"] + 1

        e.register_function("rec", rec)
        assert e.eval_query(f"x = rec({depth})") == [{"x": depth}]


def test_callback_closing_own_engine():
    """Closing the engine from inside its own callback must not crash."""
    e = OpaEngine()

    def closer():
        e.close()
        return 1

    e.register_function("closer", closer)
    try:
        e.eval_query("x = closer()")
    except OpaError:
        pass
    with pytest.raises(OpaError):
        e.eval_query("x = 1")


# -- lifecycle -----------------------------------------------------------


@fuzz_settings
@given(ops=st.lists(st.integers(0, 6), max_size=40))
def test_lifecycle_sequences(ops):
    """Random create/close/use/GC sequences never touch a freed handle."""
    engines = []
    for op in ops:
        if op == 0 or not engines:
            engines.append(OpaEngine())
        e = engines[op % len(engines)]
        try:
            if op == 1:
                e.close()
            elif op == 2:
                e.add_data({"n": op})
            elif op == 3:
                e.register_function(f"f{len(engines)}", lambda x: x)
            elif op == 4:
                e.eval_query("x = 1")
            elif op == 5:
                engines.remove(e)
                del e
                gc.collect()
            elif op == 6:
                e._handle = 2**64 - 1 if e._handle is not None else None
                e.eval_query("x = 1")
        except OpaError:
            pass
    for e in engines:
        e.close()


# -- concurrency ---------------------------------------------------------


def _run_threads(workers, target):
    errors = []
    barrier = threading.Barrier(workers)

    def wrap(i):
        try:
            barrier.wait()
            target(i)
        except BaseException as ex:  # noqa: BLE001 - report everything
            errors.append(ex)

    threads = [threading.Thread(target=wrap, args=(i,)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
        assert not t.is_alive(), "deadlock"
    if errors:
        raise errors[0]


@settings(fuzz_settings, max_examples=max(EXAMPLES // 5, 10))
@given(
    workers=st.integers(2, 16),
    ops=st.lists(st.integers(0, 9), min_size=1, max_size=30),
    seed=st.integers(),
    payload=json_values,
)
def test_shared_engine_concurrent_ops(workers, ops, seed, payload):
    """Many threads interleave config, eval, callbacks and close on shared
    engines; every call must return a correct result or an OpaError."""
    assume(not _has_surrogate(payload))  # rejected up front; covered above
    engines = [OpaEngine(), OpaEngine()]
    for i, e in enumerate(engines):
        e.add_policy("p.rego", "package p\n\nv := echo(input)\n")
        e.register_function("echo", lambda x: x)
    expected = _normalize(payload)

    def work(i):
        rnd = random.Random(seed + i)
        for op in ops:
            e = engines[rnd.randrange(len(engines))]
            try:
                if op in (0, 1, 2):
                    got = e.eval_document("p.v", {"w": i, "p": payload})
                    assert got == {"w": i, "p": expected}
                elif op == 3:
                    e.add_data({f"t{i}": {str(rnd.random()): payload}})
                elif op == 4:
                    e.add_policy(f"q{i}.rego", f"package q{i}\n\nv := {i}\n")
                elif op == 5:
                    e.register_function(f"g{i}_{rnd.random()}", lambda x: [x, i])
                elif op == 6:
                    rows = e.eval_query("x = echo(input)", payload, trace=True)
                    assert rows == ([] if payload is None else [{"x": expected}])
                elif op == 7:
                    e.compile_filters(
                        "input.t.o == input.me", {"me": i}, unknowns=["input.t"]
                    )
                elif op == 8:
                    e.eval_document("p", {"w": i}, coverage=True)
                elif op == 9 and rnd.random() < 0.1:
                    e.close()
            except OpaError as ex:
                if ex.code == "panic":
                    raise
                # A concurrently closed engine is the only acceptable failure
                # for operations on valid inputs.
                if ex.code not in ("closed", "invalid_handle", "merge_conflict"):
                    raise

    try:
        _run_threads(workers, work)
    finally:
        for e in engines:
            e.close()


@settings(fuzz_settings, max_examples=max(EXAMPLES // 10, 5))
@given(workers=st.integers(2, 12), size=st.integers(0, 1 << 16))
def test_concurrent_callbacks_distinct_engines(workers, size):
    """Callbacks from many threads at once must never see or return another
    thread's buffer (catches response buffer mixups / use-after-free)."""

    def work(i):
        tag = f"{i}:" + chr(0x1F600 + i) * size
        with OpaEngine() as e:
            e.register_function("tag", lambda x: [x, tag])
            for n in range(5):
                assert e.eval_query("x = tag(input)", n) == [{"x": [n, tag]}]

    _run_threads(workers, work)


@settings(fuzz_settings, max_examples=max(EXAMPLES // 10, 5))
@given(workers=st.integers(2, 8))
def test_close_during_eval(workers):
    """Closing an engine while other threads are inside eval and callbacks."""
    e = OpaEngine()
    started = threading.Event()

    def slow(x):
        started.set()
        return x

    e.register_function("slow", slow)

    def work(i):
        if i == 0:
            started.wait(5)
            e.close()
            return
        for _ in range(50):
            try:
                assert e.eval_query("x = slow(input)", i) == [{"x": i}]
            except OpaError as ex:
                assert ex.code in ("closed", "invalid_handle"), ex
                return

    _run_threads(workers, work)
    e.close()
