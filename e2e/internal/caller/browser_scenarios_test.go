package caller

import "testing"

func TestBrowserOperationReferencesRemainDistinctAndOrdered(t *testing.T) {
	create := browserCreateRef()
	open := browserOpenRef()
	if create.SandboxID != BrowserSandboxID || open.SandboxID != BrowserSandboxID {
		t.Fatalf("Browser sandbox identity drift: create=%#v open=%#v", create, open)
	}
	if create.OperationID == open.OperationID || create.AttemptID == open.AttemptID || create.FencingToken >= open.FencingToken {
		t.Fatalf("Browser operation scopes are not distinct and ordered: create=%#v open=%#v", create, open)
	}
}
