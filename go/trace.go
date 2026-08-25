package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

type traceEvent struct {
	Op       string         `json:"op"`
	QueryID  uint64         `json:"query_id"`
	ParentID uint64         `json:"parent_id"`
	Location string         `json:"location,omitempty"`
	Node     string         `json:"node,omitempty"`
	Locals   map[string]any `json:"locals,omitempty"`
	Message  string         `json:"message,omitempty"`
}

// traceCollector implements topdown.QueryTracer, capturing every evaluation
// event together with the local variable bindings live at that point.
type traceCollector struct {
	mu     sync.Mutex
	events []traceEvent
}

func (t *traceCollector) Enabled() bool { return true }

func (t *traceCollector) Config() topdown.TraceConfig {
	return topdown.TraceConfig{PlugLocalVars: true}
}

func (t *traceCollector) TraceEvent(evt topdown.Event) {
	te := traceEvent{
		Op:       string(evt.Op),
		QueryID:  evt.QueryID,
		ParentID: evt.ParentID,
		Message:  evt.Message,
	}
	if evt.Location != nil {
		te.Location = evt.Location.String()
	}
	if evt.Node != nil {
		te.Node = fmt.Sprintf("%v", evt.Node)
	}
	if evt.Locals != nil {
		locals := map[string]any{}
		evt.Locals.Iter(func(k, v ast.Value) bool {
			kv, ok := k.(ast.Var)
			if !ok {
				return false
			}
			name := string(kv)
			// Compiler-generated vars carry the user-facing name in the
			// event metadata; drop them if no such name exists.
			if md, found := evt.LocalMetadata[kv]; found {
				name = string(md.Name)
			}
			if strings.HasPrefix(name, "__local") || strings.HasPrefix(name, "$") {
				return false // compiler temporaries and wildcards
			}
			if j, err := ast.JSON(v); err == nil {
				locals[name] = j
			} else {
				locals[name] = v.String()
			}
			return false
		})
		if len(locals) > 0 {
			te.Locals = locals
		}
	}
	t.mu.Lock()
	t.events = append(t.events, te)
	t.mu.Unlock()
}
