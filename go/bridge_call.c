// Trampoline for invoking the host-provided callback function pointer,
// since Go cannot call C function pointers directly.
typedef char* (*opa_callback)(unsigned long long h, char* name, char* argsJson);

char* bridge_call(opa_callback cb, unsigned long long h, char* name, char* args) {
	return cb(h, name, args);
}
