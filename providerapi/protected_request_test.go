package providerapi

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
)

func TestClientIdentityAdmissionSelectsOneExactAllowedURI(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity, "spiffe://agent-platform/other-client"})
	admission, err := newClientIdentityAdmission([]string{testAllowedIdentity, "spiffe://agent-platform/other-client"})
	if err != nil {
		t.Fatal(err)
	}
	state := verifiedState(t, material.client)
	caller, err := admission.Caller(state)
	if err != nil || caller != testAllowedIdentity {
		t.Fatalf("Caller() = %q, %v", caller, err)
	}

	oneEligibleAmongMany := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{"urn:example:not-allowed", testAllowedIdentity, "https://example.test/not-allowed"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	caller, err = admission.Caller(verifiedState(t, oneEligibleAmongMany))
	if err != nil || caller != testAllowedIdentity {
		t.Fatalf("Caller(one eligible among many) = %q, %v", caller, err)
	}

	multipleEligible := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{testAllowedIdentity, "spiffe://agent-platform/other-client"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if _, err := admission.Caller(verifiedState(t, multipleEligible)); err == nil {
		t.Fatal("Caller() accepted multiple allowed URI identities")
	}

	repeatedEligible := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{testAllowedIdentity, testAllowedIdentity},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if _, err := admission.Caller(verifiedState(t, repeatedEligible)); err == nil {
		t.Fatal("Caller() accepted a repeated allowed URI identity")
	}
}

func TestClientIdentityAdmissionRejectsUnverifiedOrIneligibleState(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	admission, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Caller(tls.ConnectionState{}); err == nil {
		t.Fatal("Caller() accepted no verified chain")
	}
	other := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{"spiffe://agent-platform/other-client"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if _, err := admission.Caller(verifiedState(t, other)); err == nil {
		t.Fatal("Caller() accepted an unallowed URI identity")
	}
}

func TestProtectedFactsRequiresVerifiedCallerAndOneBoundedBearer(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	admission, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	state := verifiedState(t, material.client)
	request := &http.Request{
		TLS:    &state,
		Header: http.Header{"Authorization": []string{"Bearer header.payload.signature"}},
	}
	facts, err := admission.protectedFacts(request)
	if err != nil || facts.caller != testAllowedIdentity || facts.compactBearer != "header.payload.signature" {
		t.Fatalf("protectedFacts() = %#v, %v", facts, err)
	}

	tests := []http.Header{
		nil,
		{"Authorization": []string{"Basic ignored"}},
		{"Authorization": []string{"Bearer "}},
		{"Authorization": []string{"Bearer one", "Bearer two"}},
		{"Authorization": []string{"Bearer with space"}},
		{"Authorization": []string{"Bearer " + strings.Repeat("a", maxCompactBearerBytes+1)}},
	}
	for index, header := range tests {
		request.Header = header
		if _, err := admission.protectedFacts(request); err == nil {
			t.Fatalf("protectedFacts() accepted invalid bearer header %d", index)
		}
	}
	request.Header = http.Header{"Authorization": []string{"Bearer header.payload.signature"}}
	request.TLS = nil
	if _, err := admission.protectedFacts(request); err == nil {
		t.Fatal("protectedFacts() accepted a request without TLS state")
	}
}

func verifiedState(t *testing.T, certificate tls.Certificate) tls.ConnectionState {
	t.Helper()
	if len(certificate.Certificate) == 0 {
		t.Fatal("test certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
}
