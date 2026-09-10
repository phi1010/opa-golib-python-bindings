package main

/*
#include <stdlib.h>
typedef char* (*opa_callback)(unsigned long long h, char* name, char* argsJson);
char* bridge_call(opa_callback cb, unsigned long long h, char* name, char* args);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

func makeBuiltin(handle uint64, spec builtinSpec) func(*rego.Rego) {
	// OPA does not support variadic builtins with a return value, so a
	// variadic function (arity -1) is declared as taking a single array
	// argument; the host unpacks it into the callable's *args.
	nargs := spec.arity
	if nargs < 0 {
		nargs = 1
	}
	args := make([]types.Type, nargs)
	for i := range args {
		args[i] = types.A
	}
	decl := types.NewFunction(args, types.A)
	return rego.FunctionDyn(
		&rego.Function{
			Name:             spec.name,
			Decl:             decl,
			Nondeterministic: true,
		},
		func(_ rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {
			// The terms slice may include a trailing generated output/capture
			// term that is not an argument; trim to the declared arity.
			if len(terms) > nargs {
				terms = terms[:nargs]
			}
			args := make([]any, len(terms))
			for i, t := range terms {
				v, err := ast.JSON(t.Value)
				if err != nil {
					return nil, fmt.Errorf("%s: cannot convert argument %d: %w", spec.name, i, err)
				}
				args[i] = v
			}
			argsJSON, err := json.Marshal(args)
			if err != nil {
				return nil, err
			}
			cName := C.CString(spec.name)
			cArgs := C.CString(string(argsJSON))
			ret := C.bridge_call(spec.cb, C.ulonglong(handle), cName, cArgs)
			C.free(unsafe.Pointer(cName))
			C.free(unsafe.Pointer(cArgs))
			if ret == nil {
				return nil, fmt.Errorf("%s: callback returned NULL", spec.name)
			}
			// The callback mallocs the response buffer and transfers ownership
			// to us: copy the string out, then free with the C allocator via
			// OpaFreeString. Nothing on the host side retains the pointer.
			s := C.GoString(ret)
			C.free(unsafe.Pointer(ret))
			var envelope struct {
				Result *json.RawMessage `json:"result"`
				Error  *string          `json:"error"`
			}
			if err := json.Unmarshal([]byte(s), &envelope); err != nil {
				return nil, fmt.Errorf("%s: invalid callback response: %w", spec.name, err)
			}
			if envelope.Error != nil {
				return nil, fmt.Errorf("%s: %s", spec.name, *envelope.Error)
			}
			if envelope.Result == nil {
				// undefined
				return nil, nil
			}
			var v any
			if err := json.Unmarshal(*envelope.Result, &v); err != nil {
				return nil, err
			}
			val, err := ast.InterfaceToValue(v)
			if err != nil {
				return nil, err
			}
			return ast.NewTerm(val), nil
		},
	)
}
