package phase6security

import (
	"encoding/json"
	"testing"
)

func TestControlDeliveryDeclarationHasDistinctScopeAndHolds(t *testing.T) {
	p := testControlBootstrap(t)
	b := p.DockerControl.OperatorBootstrap
	b.Protocol = ControlDeliveryBootstrapProtocol
	b.Target = ControlDeliveryTarget
	b.ObservationProtocol = ControlDeliveryObservationProtocol
	for i := range b.Launches {
		l := &b.Launches[i]
		if l.Target == ControlBootstrapTarget {
			l.Target = ControlDeliveryTarget
			l.ProbeDigest = testDigest("probe")
		}
	}
	p.ProfileDigest = p.Digest()
	raw, _ := json.Marshal(p)
	if _, e := ReviewControlBootstrap(raw); e != nil {
		t.Fatal(e)
	}
	if p.Validate() == nil {
		t.Fatal("hold")
	}
	for name, mutate := range map[string]func(*ControlOperatorBootstrapV1){"old observation": func(b *ControlOperatorBootstrapV1) { b.ObservationProtocol = ControlOperatorObservationProtocol }, "old target": func(b *ControlOperatorBootstrapV1) { b.Target = ControlBootstrapTarget }, "old version": func(b *ControlOperatorBootstrapV1) { b.Protocol = ControlBootstrapProtocol }, "missing probe": func(b *ControlOperatorBootstrapV1) {
		for i := range b.Launches {
			b.Launches[i].ProbeDigest = ""
		}
	}, "unrelated probe": func(b *ControlOperatorBootstrapV1) {
		for i := range b.Launches {
			if b.Launches[i].Target == "core" {
				b.Launches[i].ProbeDigest = testDigest("other")
			}
		}
	}} {
		t.Run(name, func(t *testing.T) {
			var q ProfileV2
			json.Unmarshal(raw, &q)
			mutate(q.DockerControl.OperatorBootstrap)
			q.ProfileDigest = q.Digest()
			bad, _ := json.Marshal(q)
			if _, e := ReviewControlBootstrap(bad); e == nil {
				t.Fatal("version crossed")
			}
		})
	}
}

func TestControlSourceDeclarationCannotReuseProcessOnlyAuthority(t *testing.T) {
	p := testControlBootstrap(t)
	b := p.DockerControl.OperatorBootstrap
	b.Protocol = ControlSourceBootstrapProtocol
	b.Target = ControlSourceTarget
	b.ObservationProtocol = ControlSourceObservationProtocol
	for i := range b.Launches {
		l := &b.Launches[i]
		if l.Target == ControlBootstrapTarget {
			l.Target = ControlSourceTarget
			l.ProbeDigest = testDigest("source-probe")
		}
	}
	p.ProfileDigest = p.Digest()
	raw, _ := json.Marshal(p)
	review, e := ReviewControlBootstrap(raw)
	if e != nil || review.Source == nil || review.Source.Source.IntentDigest != p.DockerControl.SourceAccess.IntentDigest {
		t.Fatal("complete source declaration", e)
	}
	if p.Validate() == nil {
		t.Fatal("public admission")
	}
	if _, e := p.CodingExecutionStorageBinding(); e == nil {
		t.Fatal("Store admission")
	}
	for name, mutate := range map[string]func(*ProfileV2){
		"old domain": func(q *ProfileV2) {
			q.DockerControl.OperatorBootstrap.ObservationProtocol = ControlDeliveryObservationProtocol
		},
		"old version":    func(q *ProfileV2) { q.DockerControl.OperatorBootstrap.Protocol = ControlDeliveryBootstrapProtocol },
		"old target":     func(q *ProfileV2) { q.DockerControl.OperatorBootstrap.Target = ControlDeliveryTarget },
		"missing source": func(q *ProfileV2) { q.DockerControl.SourceAccess = nil },
		"mutable source": func(q *ProfileV2) { q.DockerControl.SourceAccess.Intent.BackingReadOnly = false },
	} {
		t.Run(name, func(t *testing.T) {
			var q ProfileV2
			json.Unmarshal(raw, &q)
			mutate(&q)
			q.ProfileDigest = q.Digest()
			doc, _ := json.Marshal(q)
			if _, e := ReviewControlBootstrap(doc); e == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}
