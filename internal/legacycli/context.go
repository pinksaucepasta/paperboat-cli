// Package legacycli is a temporary action-context compatibility layer while
// Cobra owns all command parsing. It intentionally has no parser.
package legacycli

import (
	"context"
	"flag"
	"io"
)

type ActionFunc func(*Context) error

type Context struct {
	Context context.Context
	set     *flag.FlagSet
}

func NewContext(_ *App, set *flag.FlagSet, _ *Context) *Context {
	return &Context{Context: context.Background(), set: set}
}

func (c *Context) String(name string) string { return c.set.Lookup(name).Value.String() }
func (c *Context) Bool(name string) bool {
	v, ok := c.set.Lookup(name).Value.(flag.Getter)
	if !ok {
		return false
	}
	value, _ := v.Get().(bool)
	return value
}
func (c *Context) Float64(name string) float64 {
	v, ok := c.set.Lookup(name).Value.(flag.Getter)
	if !ok {
		return 0
	}
	value, _ := v.Get().(float64)
	return value
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

type App struct {
	Writer, ErrWriter io.Writer
	RunFunc           func([]string) error
}

func (a *App) Run(args []string) error { return a.RunFunc(args) }

type Command struct {
	Name        string
	Usage       string
	ArgsUsage   string
	Flags       []Flag
	Action      ActionFunc
	Subcommands []*Command
}
type Flag interface{ isFlag() }
type StringFlag struct{ Name, Usage string }

func (*StringFlag) isFlag() {}

type BoolFlag struct{ Name, Usage string }

func (*BoolFlag) isFlag() {}

type Float64Flag struct{ Name, Usage string }

func (*Float64Flag) isFlag() {}
