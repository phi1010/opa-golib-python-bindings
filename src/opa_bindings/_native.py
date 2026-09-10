"""ctypes bindings for the Go c-shared bridge library."""

import ctypes
from pathlib import Path

_LIB_PATH = Path(__file__).parent / "libopabridge.so"

# char* (*opa_callback)(unsigned long long h, char* name, char* argsJson)
# Return type is c_void_p so ctypes does not copy/free. The buffer is
# malloc'd by the host with the C allocator and ownership transfers to the
# Go side, which copies it and frees it with the same allocator; nothing on
# the Python side retains the pointer.
CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p
)


def load():
    lib = ctypes.CDLL(str(_LIB_PATH))

    lib.OpaNew.restype = ctypes.c_uint64
    lib.OpaNew.argtypes = []

    lib.OpaDestroy.restype = None
    lib.OpaDestroy.argtypes = [ctypes.c_uint64]

    lib.OpaFreeString.restype = None
    lib.OpaFreeString.argtypes = [ctypes.c_void_p]

    # Fallible calls return a malloc'd char* envelope; declare as c_void_p so
    # we can free it after copying.
    lib.OpaAddPolicy.restype = ctypes.c_void_p
    lib.OpaAddPolicy.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]

    lib.OpaAddData.restype = ctypes.c_void_p
    lib.OpaAddData.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]

    lib.OpaRegisterBuiltin.restype = ctypes.c_void_p
    lib.OpaRegisterBuiltin.argtypes = [
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_int,
        CALLBACK,
    ]

    lib.OpaEvalQuery.restype = ctypes.c_void_p
    lib.OpaEvalQuery.argtypes = [
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,  # coverage
        ctypes.c_int,  # trace
    ]

    lib.OpaEvalDocument.restype = ctypes.c_void_p
    lib.OpaEvalDocument.argtypes = [
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,  # coverage
        ctypes.c_int,  # trace
    ]

    lib.OpaCompileFilters.restype = ctypes.c_void_p
    lib.OpaCompileFilters.argtypes = [
        ctypes.c_uint64,
        ctypes.c_char_p,  # query
        ctypes.c_char_p,  # input JSON
        ctypes.c_char_p,  # unknowns JSON array
        ctypes.c_char_p,  # target
        ctypes.c_char_p,  # dialect
        ctypes.c_char_p,  # mappings JSON
        ctypes.c_char_p,  # mask rule ref
    ]

    return lib
