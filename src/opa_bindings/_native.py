"""ctypes bindings for the Go c-shared bridge library."""

import ctypes
from pathlib import Path

_LIB_PATH = Path(__file__).parent / "libopabridge.so"

# char* (*opa_callback)(unsigned long long h, char* name, char* argsJson)
# Return type is c_void_p so ctypes does not copy/free: the Python side keeps
# the returned buffer alive until the callback is invoked again, and Go copies
# it synchronously.
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
    lib.OpaEvalQuery.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]

    lib.OpaEvalDocument.restype = ctypes.c_void_p
    lib.OpaEvalDocument.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]

    return lib
