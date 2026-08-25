package main

/*
#include <stdlib.h>

// Callback provided by the host (Python). It receives the engine handle, the
// builtin name and the arguments as a JSON array. It returns a pointer to a
// JSON envelope {"result": ...} or {"error": "..."}. The buffer is owned by
// the host and must stay valid until the callback is invoked again; the Go
// side copies it synchronously.
typedef char* (*opa_callback)(unsigned long long h, char* name, char* argsJson);
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/cover"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

type printMsg struct {
	Message  string `json:"message"`
	Location string `json:"location"`
}

// printCollector implements print.Hook, collecting print() output per eval.
type printCollector struct {
	mu   sync.Mutex
	msgs []printMsg
}

func (p *printCollector) Print(pctx print.Context, msg string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	loc := ""
	if pctx.Location != nil {
		loc = pctx.Location.String()
	}
	p.msgs = append(p.msgs, printMsg{Message: msg, Location: loc})
	return nil
}

type builtinSpec struct {
	name  string
	arity int // -1 = variadic
	cb    C.opa_callback
}

type engine struct {
	mu       sync.Mutex
	modules  map[string]string
	data     map[string]any
	builtins []builtinSpec
	prepared map[string]rego.PreparedEvalQuery
}

var (
	registry   = map[uint64]*engine{}
	registryMu sync.Mutex
	nextHandle uint64
)

func getEngine(h C.ulonglong) (*engine, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	e, ok := registry[uint64(h)]
	if !ok {
		return nil, fmt.Errorf("invalid engine handle %d", uint64(h))
	}
	return e, nil
}

func resultJSON(v any) *C.char {
	b, err := json.Marshal(map[string]any{"result": v})
	if err != nil {
		return errorJSON("internal", err.Error())
	}
	return C.CString(string(b))
}

func errorJSON(code, msg string) *C.char {
	b, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": msg}})
	return C.CString(string(b))
}

//export OpaNew
func OpaNew() C.ulonglong {
	registryMu.Lock()
	defer registryMu.Unlock()
	nextHandle++
	registry[nextHandle] = &engine{
		modules:  map[string]string{},
		data:     map[string]any{},
		prepared: map[string]rego.PreparedEvalQuery{},
	}
	return C.ulonglong(nextHandle)
}

//export OpaDestroy
func OpaDestroy(h C.ulonglong) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, uint64(h))
}

//export OpaFreeString
func OpaFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

//export OpaAddPolicy
func OpaAddPolicy(h C.ulonglong, path, src *C.char) *C.char {
	e, err := getEngine(h)
	if err != nil {
		return errorJSON("invalid_handle", err.Error())
	}
	p, s := C.GoString(path), C.GoString(src)
	if _, err := ast.ParseModule(p, s); err != nil {
		return errorJSON("parse_error", err.Error())
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules[p] = s
	e.prepared = map[string]rego.PreparedEvalQuery{}
	return resultJSON(true)
}

//export OpaAddData
func OpaAddData(h C.ulonglong, dataPath, jsonValue *C.char) *C.char {
	e, err := getEngine(h)
	if err != nil {
		return errorJSON("invalid_handle", err.Error())
	}
	var v any
	if err := json.Unmarshal([]byte(C.GoString(jsonValue)), &v); err != nil {
		return errorJSON("invalid_json", err.Error())
	}
	// Wrap the value in nested objects along dataPath.
	p := C.GoString(dataPath)
	segs := []string{}
	if p != "" {
		segs = strings.Split(p, ".")
	}
	for i := len(segs) - 1; i >= 0; i-- {
		v = map[string]any{segs[i]: v}
	}
	src, ok := v.(map[string]any)
	if !ok {
		return errorJSON("merge_conflict", "root data value must be a JSON object")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	merged, err := deepMerge(e.data, src, "data")
	if err != nil {
		return errorJSON("merge_conflict", err.Error())
	}
	e.data = merged
	e.prepared = map[string]rego.PreparedEvalQuery{}
	return resultJSON(true)
}

//export OpaRegisterBuiltin
func OpaRegisterBuiltin(h C.ulonglong, name *C.char, arity C.int, cb C.opa_callback) *C.char {
	e, err := getEngine(h)
	if err != nil {
		return errorJSON("invalid_handle", err.Error())
	}
	n := C.GoString(name)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.builtins {
		if b.name == n {
			return errorJSON("already_registered", "builtin already registered: "+n)
		}
	}
	e.builtins = append(e.builtins, builtinSpec{name: n, arity: int(arity), cb: cb})
	e.prepared = map[string]rego.PreparedEvalQuery{}
	return resultJSON(true)
}

//export OpaEvalQuery
func OpaEvalQuery(h C.ulonglong, query, inputJson *C.char, coverage, trace C.int) *C.char {
	return evalCommon(h, C.GoString(query), inputJson, coverage != 0, trace != 0)
}

//export OpaEvalDocument
func OpaEvalDocument(h C.ulonglong, docPath, inputJson *C.char, coverage, trace C.int) *C.char {
	p := C.GoString(docPath)
	q := "data"
	if p != "" {
		q = "data." + p
	}
	return evalCommon(h, q, inputJson, coverage != 0, trace != 0)
}

func evalCommon(h C.ulonglong, query string, inputJson *C.char, coverage, trace bool) *C.char {
	e, err := getEngine(h)
	if err != nil {
		return errorJSON("invalid_handle", err.Error())
	}
	e.mu.Lock()
	pq, ok := e.prepared[query]
	if !ok {
		opts := []func(*rego.Rego){
			rego.Query(query),
			rego.Store(inmem.NewFromObject(e.data)),
			rego.StrictBuiltinErrors(true),
			rego.EnablePrintStatements(true),
		}
		for path, src := range e.modules {
			opts = append(opts, rego.Module(path, src))
		}
		for _, b := range e.builtins {
			opts = append(opts, makeBuiltin(uint64(h), b))
		}
		pq, err = rego.New(opts...).PrepareForEval(context.Background())
		if err != nil {
			e.mu.Unlock()
			return errorJSON("prepare_error", err.Error())
		}
		e.prepared[query] = pq
	}
	e.mu.Unlock()

	evalOpts := []rego.EvalOption{}
	if inputJson != nil {
		s := C.GoString(inputJson)
		if s != "" {
			var input any
			if err := json.Unmarshal([]byte(s), &input); err != nil {
				return errorJSON("invalid_json", err.Error())
			}
			evalOpts = append(evalOpts, rego.EvalInput(input))
		}
	}
	collector := &printCollector{}
	evalOpts = append(evalOpts, rego.EvalPrintHook(collector))
	var cov *cover.Cover
	if coverage {
		cov = cover.New()
		evalOpts = append(evalOpts, rego.EvalQueryTracer(cov))
	}
	var tracer *traceCollector
	if trace {
		tracer = &traceCollector{}
		evalOpts = append(evalOpts, rego.EvalQueryTracer(tracer))
	}
	rs, err := pq.Eval(context.Background(), evalOpts...)
	if err != nil {
		return errorJSON("eval_error", err.Error())
	}
	envelope := map[string]any{"result": rs, "prints": collector.msgs}
	if cov != nil {
		e.mu.Lock()
		parsed := map[string]*ast.Module{}
		for path, src := range e.modules {
			if m, perr := ast.ParseModule(path, src); perr == nil {
				parsed[path] = m
			}
		}
		e.mu.Unlock()
		envelope["coverage"] = cov.Report(parsed)
	}
	if tracer != nil {
		envelope["trace"] = tracer.events
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return errorJSON("internal", err.Error())
	}
	return C.CString(string(b))
}

func main() {}
