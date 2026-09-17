package qualificationoperator

import (
	"fmt"
	"strings"
	"testing"
)

func TestProcStartTimeUsesStableFieldWithComplexCommandName(t *testing.T) {
	fields := []string{"S"}
	for value := 1; value <= 18; value++ {
		fields = append(fields, fmt.Sprint(value))
	}
	fields = append(fields, "424242", "23", "24")
	first := []byte("321 (caller gateway) worker) " + strings.Join(fields, " ") + "\n")

	mutated := append([]string(nil), fields...)
	mutated[11] = "9999"
	mutated[12] = "8888"
	second := []byte("321 (caller gateway) worker) " + strings.Join(mutated, " ") + "\n")

	for name, document := range map[string][]byte{"first": first, "mutable accounting changed": second} {
		t.Run(name, func(t *testing.T) {
			got, ok := procStartTime(document)
			if !ok || got != "424242" {
				t.Fatalf("procStartTime() = %q, %t", got, ok)
			}
		})
	}
}

func TestProcStartTimeRejectsMalformedRecords(t *testing.T) {
	for _, document := range [][]byte{
		[]byte("missing delimiter"),
		[]byte("1 (short) S 1 2 3"),
		[]byte("1 (bad) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 nope"),
	} {
		if got, ok := procStartTime(document); ok || got != "" {
			t.Fatalf("malformed record accepted: %q, %t", got, ok)
		}
	}
}
