//go:build phase6slice6gate

package productphase6gate

import (
	"slices"
	"testing"
)

func TestSlice6PostgresMountsMatchIndependentOrderAndDrift(t *testing.T) {
	effective := []slice6PostgresObservedMount{
		{Name: "config", Kind: "volume", Destination: "/pg", Writable: true},
		{Name: "data", Kind: "volume", Destination: "/data", Writable: true},
	}
	declared := []slice6PostgresObservedMount{
		{Name: "config", Kind: "volume", Destination: "/pg", NoCopy: true},
		{Name: "data", Kind: "volume", Destination: "/data", NoCopy: true},
	}
	for _, reverseEffective := range []bool{false, true} {
		for _, reverseDeclared := range []bool{false, true} {
			actualEffective, actualDeclared := slices.Clone(effective), slices.Clone(declared)
			if reverseEffective {
				slices.Reverse(actualEffective)
			}
			if reverseDeclared {
				slices.Reverse(actualDeclared)
			}
			if !slice6PostgresMountsMatch(actualEffective, actualDeclared, "config", "data") {
				t.Fatalf("rejected exact mounts at order effective=%t declared=%t", reverseEffective, reverseDeclared)
			}
		}
	}
	for name, mutate := range map[string]func(*[]slice6PostgresObservedMount, *[]slice6PostgresObservedMount){
		"missing effective": func(e, _ *[]slice6PostgresObservedMount) { *e = (*e)[:1] },
		"missing declared":  func(_, d *[]slice6PostgresObservedMount) { *d = (*d)[:1] },
		"extra destination": func(e, _ *[]slice6PostgresObservedMount) {
			*e = append(*e, slice6PostgresObservedMount{Name: "extra", Kind: "volume", Destination: "/other", Writable: true})
		},
		"duplicate effective": func(e, _ *[]slice6PostgresObservedMount) { (*e)[1].Destination = "/pg" },
		"duplicate declared":  func(_, d *[]slice6PostgresObservedMount) { (*d)[1].Destination = "/pg" },
		"wrong effective volume": func(e, _ *[]slice6PostgresObservedMount) {
			(*e)[0].Name = "other"
		},
		"wrong declared volume": func(_, d *[]slice6PostgresObservedMount) {
			(*d)[1].Name = "other"
		},
		"wrong effective type": func(e, _ *[]slice6PostgresObservedMount) { (*e)[0].Kind = "bind" },
		"wrong declared type":  func(_, d *[]slice6PostgresObservedMount) { (*d)[0].Kind = "bind" },
		"read-only effective":  func(e, _ *[]slice6PostgresObservedMount) { (*e)[0].Writable = false },
		"copy-enabled declared": func(_, d *[]slice6PostgresObservedMount) {
			(*d)[0].NoCopy = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			actualEffective, actualDeclared := slices.Clone(effective), slices.Clone(declared)
			mutate(&actualEffective, &actualDeclared)
			if slice6PostgresMountsMatch(actualEffective, actualDeclared, "config", "data") {
				t.Fatal("unreviewed PostgreSQL mount accepted")
			}
		})
	}
}
