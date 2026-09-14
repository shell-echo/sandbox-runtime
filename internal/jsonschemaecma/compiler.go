// Package jsonschemaecma creates JSON Schema compilers with the Unicode
// ECMA-262 regular-expression dialect recommended by JSON Schema 2020-12.
package jsonschemaecma

import (
	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type ecmaRegexp regexp2.Regexp

func (regexp *ecmaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(regexp).MatchString(value)
	return err == nil && matched
}

func (regexp *ecmaRegexp) String() string {
	return (*regexp2.Regexp)(regexp).String()
}

func compile(pattern string) (jsonschema.Regexp, error) {
	regexp, err := regexp2.Compile(pattern, regexp2.ECMAScript|regexp2.Unicode)
	if err != nil {
		return nil, err
	}
	return (*ecmaRegexp)(regexp), nil
}

// NewCompiler returns a draft 2020-12 compiler that asserts formats and uses
// one consistent Unicode ECMA-262 regular-expression engine for every schema
// resource.
func NewCompiler() *jsonschema.Compiler {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseRegexpEngine(compile)
	return compiler
}
