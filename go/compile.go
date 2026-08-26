package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	regocompile "github.com/open-policy-agent/opa/v1/rego/compile"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// OpaCompileFilters partially evaluates a query with respect to the given
// unknowns and translates the residual into a data filter for the given
// target/dialect ("sql" with postgresql/mysql/sqlserver/sqlite, or "ucast"
// with all/prisma/linq/""). The result envelope holds
// {"query": <string or object>, "masks": <object or null>}.
//
//export OpaCompileFilters
func OpaCompileFilters(h C.ulonglong, query, inputJson, unknownsJson, target, dialect, mappingsJson, maskRule *C.char) *C.char {
	e, err := getEngine(h)
	if err != nil {
		return errorJSON("invalid_handle", err.Error())
	}

	parsedQuery, err := ast.ParseBody(C.GoString(query))
	if err != nil {
		return errorJSON("parse_error", err.Error())
	}

	var unknownStrs []string
	if err := json.Unmarshal([]byte(C.GoString(unknownsJson)), &unknownStrs); err != nil {
		return errorJSON("invalid_json", err.Error())
	}
	unknowns := make([]*ast.Term, len(unknownStrs))
	for i, u := range unknownStrs {
		if unknowns[i], err = ast.ParseTerm(u); err != nil {
			return errorJSON("parse_error", "unknown "+u+": "+err.Error())
		}
	}

	tgt, dia := C.GoString(target), C.GoString(dialect)
	copts := []regocompile.CompileOption{
		regocompile.ParsedQuery(parsedQuery),
		regocompile.ParsedUnknowns(unknowns...),
		regocompile.Target(tgt, dia),
	}

	if s := C.GoString(mappingsJson); s != "" {
		var mappings map[string]any
		if err := json.Unmarshal([]byte(s), &mappings); err != nil {
			return errorJSON("invalid_json", err.Error())
		}
		copts = append(copts, regocompile.Mappings(mappings))
	}

	if s := C.GoString(maskRule); s != "" {
		ref, err := ast.ParseRef(s)
		if err != nil {
			return errorJSON("parse_error", "mask rule: "+err.Error())
		}
		copts = append(copts, regocompile.MaskRule(ref))
	}

	e.mu.Lock()
	ropts := []func(*rego.Rego){
		rego.Store(inmem.NewFromObject(e.data)),
		rego.StrictBuiltinErrors(true),
	}
	for path, src := range e.modules {
		ropts = append(ropts, rego.Module(path, src))
	}
	for _, b := range e.builtins {
		ropts = append(ropts, makeBuiltin(uint64(h), b))
	}
	e.mu.Unlock()
	copts = append(copts, regocompile.Rego(ropts...))

	prepared, err := regocompile.New(copts...).Prepare(context.Background())
	if err != nil {
		return errorJSON("prepare_error", err.Error())
	}

	evalOpts := []rego.EvalOption{}
	if inputJson != nil {
		if s := C.GoString(inputJson); s != "" {
			var input any
			if err := json.Unmarshal([]byte(s), &input); err != nil {
				return errorJSON("invalid_json", err.Error())
			}
			evalOpts = append(evalOpts, rego.EvalInput(input))
		}
	}

	filters, err := prepared.Compile(context.Background(), evalOpts...)
	if err != nil {
		return errorJSON("compile_error", err.Error())
	}
	f := filters.For(tgt, dia)
	return resultJSON(map[string]any{"query": f.Query, "masks": f.Masks})
}
