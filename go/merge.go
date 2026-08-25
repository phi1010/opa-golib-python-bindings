package main

import (
	"fmt"
	"reflect"
)

// deepMerge merges src into dst, returning the merged object. Objects merge
// recursively; identical non-object values are kept; anything else is a
// conflict reported with its path.
func deepMerge(dst, src map[string]any, path string) (map[string]any, error) {
	out := make(map[string]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, sv := range src {
		p := path + "." + k
		dv, exists := out[k]
		if !exists {
			out[k] = sv
			continue
		}
		dm, dIsObj := dv.(map[string]any)
		sm, sIsObj := sv.(map[string]any)
		switch {
		case dIsObj && sIsObj:
			merged, err := deepMerge(dm, sm, p)
			if err != nil {
				return nil, err
			}
			out[k] = merged
		case reflect.DeepEqual(dv, sv):
			// identical values, keep as-is
		default:
			return nil, fmt.Errorf("conflicting values at %s: cannot merge %T with %T", p, dv, sv)
		}
	}
	return out, nil
}
