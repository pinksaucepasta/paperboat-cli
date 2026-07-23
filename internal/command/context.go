// Package command defines the injected action boundary used by the Cobra
// command tree. It does not parse process arguments or write global output.
package command

import (
	"context"
	"flag"
	"io"
)

type Action func(*Context) error

type Context struct {
	Context   context.Context
	Writer    io.Writer
	ErrWriter io.Writer
	set       *flag.FlagSet
}

func NewContext(set *flag.FlagSet) *Context {
	return &Context{Context: context.Background(), set: set}
}

func (c *Context) String(name string) string { return c.set.Lookup(name).Value.String() }
func (c *Context) Bool(name string) bool {
	value, ok := c.set.Lookup(name).Value.(flag.Getter)
	if !ok {
		return false
	}
	result, _ := value.Get().(bool)
	return result
}
func (c *Context) Float64(name string) float64 {
	value, ok := c.set.Lookup(name).Value.(flag.Getter)
	if !ok {
		return 0
	}
	result, _ := value.Get().(float64)
	return result
}
func (c *Context) Args() Args { return Args{values: c.set.Args()} }

type Args struct{ values []string }

func (a Args) First() string { return a.Get(0) }
func (a Args) Get(index int) string {
	if index < 0 || index >= len(a.values) {
		return ""
	}
	return a.values[index]
}
func (a Args) Len() int { return len(a.values) }

// Spec is an internal command description consumed by the Cobra root. It
// keeps workflow construction independent from Cobra's parser types.
type Spec struct {
	Name, Usage, ArgsUsage string
	Flags                  []Flag
	Action                 Action
	Subcommands            []*Spec
}

type Flag interface{ isFlag() }
type StringFlag struct{ Name, Usage string }

func (*StringFlag) isFlag() {}

type BoolFlag struct{ Name, Usage string }

func (*BoolFlag) isFlag() {}

type Float64Flag struct{ Name, Usage string }

func (*Float64Flag) isFlag() {}

// App is retained only as an injected test runner for command transcripts.
// Production parsing starts directly at the Cobra root.
type App struct {
	Writer, ErrWriter io.Writer
	RunFunc           func([]string) error
}

func (a *App) Run(args []string) error { return a.RunFunc(args) }
