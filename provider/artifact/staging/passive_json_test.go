package staging

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

func TestPassiveJSONPolicy(t *testing.T) {
	checker := NewPassiveJSONChecker()
	request := stagingRequest([]byte(`{"ok":true}`))
	request.ExpectedMediaType = "application/json"
	for _, test := range []struct {
		name    string
		content string
		want    artifact.CheckStatus
	}{
		{"object", `{"ok":true,"nested":{"a":null},"array":[1,"x"]}`, artifact.CheckPassed},
		{"scalar", `"data"`, artifact.CheckPassed},
		{"surrogate pair", `{"emoji":"\uD83D\uDE00"}`, artifact.CheckPassed},
		{"escaped key collision", `{"a":1,"\u0061":2}`, artifact.CheckFailed},
		{"nested duplicate", `{"inner":{"x":1,"x":2}}`, artifact.CheckFailed},
		{"unpaired high surrogate", `{"x":"\uD83D"}`, artifact.CheckFailed},
		{"unpaired low surrogate", `{"x":"\uDE00"}`, artifact.CheckFailed},
		{"high followed by text", `{"x":"\uD83Da"}`, artifact.CheckFailed},
		{"trailing document", `{} {}`, artifact.CheckFailed},
		{"trailing junk", `{} trailing`, artifact.CheckFailed},
		{"comment", `{"x":1 /* comment */}`, artifact.CheckFailed},
		{"executable format", `<script>alert(1)</script>`, artifact.CheckFailed},
		{"empty", ``, artifact.CheckFailed},
		{"string limit", `"` + strings.Repeat("x", PassiveJSONMaxStringBytes+1) + `"`, artifact.CheckFailed},
		{"number limit", strings.Repeat("1", PassiveJSONMaxStringBytes+1), artifact.CheckFailed},
		{"depth limit", strings.Repeat("[", PassiveJSONMaxDepth+1) + `0` + strings.Repeat("]", PassiveJSONMaxDepth+1), artifact.CheckFailed},
		{"token limit", `[` + strings.Repeat(`0,`, PassiveJSONMaxTokens) + `0]`, artifact.CheckFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, err := checker.CheckContent(context.Background(), request, []byte(test.content))
			if err != nil || status != test.want {
				t.Fatalf("CheckContent = %s, %v; want %s", status, err, test.want)
			}
		})
	}
	status, err := checker.CheckContent(context.Background(), request, []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})
	if err != nil || status != artifact.CheckFailed {
		t.Fatalf("invalid UTF-8 = %s, %v", status, err)
	}
	request.ExpectedMediaType = "text/plain"
	status, err = checker.CheckContent(context.Background(), request, []byte(`{"ok":true}`))
	if err != nil || status != artifact.CheckFailed {
		t.Fatalf("unsupported MIME = %s, %v", status, err)
	}
}

type cancelAfterChecks struct {
	context.Context
	remaining int
}

type countChecks struct {
	context.Context
	calls  int
	failAt int
}

func (c *countChecks) Err() error {
	c.calls++
	if c.failAt > 0 && c.calls >= c.failAt {
		return context.Canceled
	}
	return nil
}

func TestPassiveJSONSyntaxAndExactPolicyLimits(t *testing.T) {
	valid := []string{
		`{"object":{"array":[true,false,null,-0,12.3e+4],"empty":{}},"unicode":"你好😀"}`,
		`"\\\"\/\b\f\n\r\t\u002f"`,
		`-0`, `0`, `1.0`, `1e-2`, `1E+2`,
		strings.Repeat("[", PassiveJSONMaxDepth) + `0` + strings.Repeat("]", PassiveJSONMaxDepth),
		`[` + strings.Repeat(`0,`, PassiveJSONMaxTokens-2) + `0]`,
		strings.Repeat(" ", 1<<20) + `{}` + strings.Repeat("\n", 1<<20),
		`{"` + strings.Repeat("k", PassiveJSONMaxStringBytes) + `":0}`,
		`{"` + strings.Repeat(`\u0061`, PassiveJSONMaxStringBytes) + `":0}`,
	}
	for index, sample := range valid {
		content := []byte(sample)
		if !json.Valid(content) || parsePassiveJSON(context.Background(), content) != nil {
			t.Fatalf("valid policy sample %d rejected", index)
		}
	}
	invalid := []string{
		`+1`, `01`, `-.1`, `1.`, `1e`, `1e+`, `-`,
		strings.Repeat("[", PassiveJSONMaxDepth+1) + `0` + strings.Repeat("]", PassiveJSONMaxDepth+1),
		`[` + strings.Repeat(`0,`, PassiveJSONMaxTokens-1) + `0]`,
		`{"` + strings.Repeat("k", PassiveJSONMaxStringBytes+1) + `":0}`,
		`{"` + strings.Repeat(`\u0061`, PassiveJSONMaxStringBytes+1) + `":0}`,
		`{"a":1,"\u0061":2}`,
	}
	for index, sample := range invalid {
		if parsePassiveJSON(context.Background(), []byte(sample)) == nil {
			t.Fatalf("invalid syntax/policy sample %d accepted", index)
		}
	}
}

func TestPassiveJSONCancellationAtBoundedKeyDecode(t *testing.T) {
	content := []byte(`{"` + strings.Repeat(`\u0061`, PassiveJSONMaxStringBytes) + `":0}`)
	baseline := &countChecks{Context: context.Background()}
	if err := parsePassiveJSON(baseline, content); err != nil {
		t.Fatal(err)
	}
	if baseline.calls < 1000 {
		t.Fatalf("large key did not exercise bounded cancellation checks: %d", baseline.calls)
	}
	for _, failAt := range []int{baseline.calls - 3, baseline.calls - 1} {
		ctx := &countChecks{Context: context.Background(), failAt: failAt}
		if err := parsePassiveJSON(ctx, content); err != context.Canceled {
			t.Fatalf("key decode cancellation at check %d = %v", failAt, err)
		}
	}
}

func (c *cancelAfterChecks) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestPassiveJSONBoundariesAndInFlightCancellation(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`"` + strings.Repeat("x", PassiveJSONMaxStringBytes) + `"`),
		[]byte(`"` + strings.Repeat(`\u0061`, PassiveJSONMaxStringBytes) + `"`),
		[]byte(strings.Repeat("1", PassiveJSONMaxStringBytes)),
	} {
		if err := parsePassiveJSON(context.Background(), content); err != nil {
			t.Fatalf("exact token boundary rejected: %v", err)
		}
	}
	for _, content := range [][]byte{
		[]byte(`"` + strings.Repeat(`\u0061`, PassiveJSONMaxStringBytes+1) + `"`),
		[]byte(strings.Repeat("1", PassiveJSONMaxStringBytes+1)),
	} {
		if err := parsePassiveJSON(context.Background(), content); err == nil {
			t.Fatal("limit+1 token accepted")
		}
	}
	maximum := bytes.Repeat([]byte{' '}, artifact.MaxArtifactBytes)
	maximum[len(maximum)-2], maximum[len(maximum)-1] = '{', '}'
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := parsePassiveJSON(context.Background(), maximum); err != nil {
		t.Fatalf("legal 64 MiB total document rejected: %v", err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Fatalf("64 MiB policy parse allocated %d bytes beyond its input buffer", allocated)
	}
	for _, content := range [][]byte{
		[]byte(strings.Repeat(" ", 2<<20) + `{}`),
		[]byte(`"` + strings.Repeat("x", PassiveJSONMaxStringBytes) + `"`),
		[]byte(strings.Repeat("1", PassiveJSONMaxStringBytes)),
	} {
		ctx := &cancelAfterChecks{Context: context.Background(), remaining: 16}
		if err := parsePassiveJSON(ctx, content); err != context.Canceled {
			t.Fatalf("in-flight cancellation = %v", err)
		}
		ctx = &cancelAfterChecks{Context: context.Background(), remaining: 16}
		if _, err := detectMediaType(ctx, content); err != context.Canceled {
			t.Fatalf("MIME cancellation became fallback = %v", err)
		}
	}
}

func TestPassiveJSONNeverAcceptsSyntaxRejectedByStandardJSON(t *testing.T) {
	random := rand.New(rand.NewSource(6))
	alphabet := []byte(`{}[],:"\\tnruealsf0123456789-+. /`)
	for i := 0; i < 5000; i++ {
		content := make([]byte, random.Intn(40))
		for j := range content {
			content[j] = alphabet[random.Intn(len(alphabet))]
		}
		if parsePassiveJSON(context.Background(), content) == nil && !json.Valid(content) {
			t.Fatalf("policy accepted invalid JSON %q", content)
		}
	}
}

func TestPassiveJSONCancellationAndMIMEDetection(t *testing.T) {
	checker := NewPassiveJSONChecker()
	request := stagingRequest([]byte(`{"ok":true}`))
	request.ExpectedMediaType = "application/json"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if status, err := checker.CheckContent(ctx, request, []byte(`{"ok":true}`)); status != artifact.CheckNotRun || err != context.Canceled {
		t.Fatalf("cancelled check = %s, %v", status, err)
	}
	if got, err := detectMediaType(context.Background(), []byte(`{"ok":true}`)); err != nil || got != "application/json" {
		t.Fatalf("valid JSON MIME = %q", got)
	}
	if got, err := detectMediaType(context.Background(), []byte(`<script>alert(1)</script>`)); err != nil || got == "application/json" {
		t.Fatalf("active content MIME = %q", got)
	}
}

func TestStagerIgnoresExtensionAndRunsPassiveJSONBeforeMalware(t *testing.T) {
	content := []byte(`{"ok":true}`)
	request := stagingRequest(content)
	request.SourcePath = "/outputs/report.txt"
	request.ExpectedMediaType = "application/json"
	malware := &testContentChecker{status: artifact.CheckPassed}
	stager, err := New(testOutputReader{content: content}, testTenantChecker{status: artifact.CheckPassed}, NewPassiveJSONChecker(), malware, t.TempDir(), ClockFunc(func() time.Time { return stagerTestTime }))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := stager.Stage(context.Background(), request, stagerTestTime)
	if err != nil || evidence.Status != artifact.StatusStaged || malware.calls != 1 {
		t.Fatalf("JSON staged = %#v, %v; malware calls=%d", evidence, err, malware.calls)
	}

	request.SourcePath = "/outputs/report.json"
	request.ExpectedMediaType = "text/plain"
	evidence, err = stager.Stage(context.Background(), request, stagerTestTime)
	if err != nil || evidence.Status != artifact.StatusRejected || evidence.MediaType != "application/json" || malware.calls != 1 {
		t.Fatalf("extension/MIME mismatch = %#v, %v; malware calls=%d", evidence, err, malware.calls)
	}

	bad := []byte(`<script>alert(1)</script>`)
	badRequest := stagingRequest(bad)
	badRequest.SourcePath = "/outputs/unsafe.json"
	badRequest.ExpectedMediaType = "text/html"
	stager, err = New(testOutputReader{content: bad}, testTenantChecker{status: artifact.CheckPassed}, NewPassiveJSONChecker(), malware, t.TempDir(), ClockFunc(func() time.Time { return stagerTestTime }))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = stager.Stage(context.Background(), badRequest, stagerTestTime)
	if err != nil || evidence.Status != artifact.StatusRejected || evidence.ActiveContentCheck.Status != artifact.CheckFailed || malware.calls != 1 {
		t.Fatalf("unsupported active content = %#v, %v; malware calls=%d", evidence, err, malware.calls)
	}
}

func TestStagerCancellationAtMIMEClassificationNeverRunsChecksOrStages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	content := []byte(`{"ok":true}`)
	request := stagingRequest(content)
	request.ExpectedMediaType = "application/json"
	request.SourcePath = "/outputs/report.json"
	active := &testContentChecker{status: artifact.CheckPassed}
	malware := &testContentChecker{status: artifact.CheckPassed}
	calls := 0
	root := t.TempDir()
	stager, err := New(testOutputReader{content: content}, testTenantChecker{status: artifact.CheckPassed}, active, malware, root, ClockFunc(func() time.Time {
		calls++
		if calls == 3 { // immediately before MIME classification
			cancel()
		}
		return stagerTestTime
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(ctx, request, stagerTestTime); err != context.Canceled {
		t.Fatalf("classification cancellation = %v", err)
	}
	if active.calls != 0 || malware.calls != 0 {
		t.Fatalf("checks ran after classification cancellation: %d/%d", active.calls, malware.calls)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging entries after cancellation = %d, %v", len(entries), err)
	}
}
