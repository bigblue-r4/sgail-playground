//go:build js && wasm

// The browser entry point: a global `witness` object whose methods change the
// in-memory log and return the new state as JSON ({"state": ..., "error": ...}).
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/bigblue-r4/sgail-playground/witness/demo"
)

var ses *demo.Session

func reply(err error) any {
	out := map[string]any{"state": ses.State()}
	if err != nil {
		out["error"] = err.Error()
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func reset() error {
	s, err := demo.NewSession()
	if err == nil {
		ses = s
	}
	return err
}

func method(f func(args []js.Value) error) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any { return reply(f(args)) })
}

func main() {
	if err := reset(); err != nil {
		panic(err)
	}
	js.Global().Set("witness", js.ValueOf(map[string]any{
		"state":      method(func([]js.Value) error { return nil }),
		"reset":      method(func([]js.Value) error { return reset() }),
		"edit":       method(func(a []js.Value) error { return ses.Edit(a[0].Int(), a[1].String()) }),
		"remove":     method(func(a []js.Value) error { return ses.Delete(a[0].Int()) }),
		"truncate":   method(func(a []js.Value) error { ses.Truncate(a[0].Int()); return nil }),
		"deleteHead": method(func([]js.Value) error { ses.DeleteHead(); return nil }),
		"resign":     method(func([]js.Value) error { return ses.Resign() }),
	}))
	select {} // keep the Go side alive for the page
}
