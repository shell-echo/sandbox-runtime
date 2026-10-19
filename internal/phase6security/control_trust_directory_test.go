package phase6security

import (
	"bytes"
	"encoding/json"
	"testing"
)

func testControlTrustDirectories(p *ProfileV2, digest string) {
	for i := range p.TrustAnchors {
		a := &p.TrustAnchors[i]
		if a.ID != "internal-client-ca" && a.ID != "internal-server-ca" {
			continue
		}
		a.MountDirectory = "/run/trust/" + a.ID
		a.TargetPath = a.MountDirectory + "/bundle.pem"
		if digest != "" {
			a.BundleDigest = digest
		}
		for j := range p.Principals {
			for k := range p.Principals[j].Mounts {
				m := &p.Principals[j].Mounts[k]
				if m.Kind == "trust_anchor" && m.StorageID == a.StorageID {
					m.Target = a.MountDirectory
				}
			}
		}
	}
}

func testControlTrust(t *testing.T) ProfileV2 {
	t.Helper()
	p := testControlBootstrap(t)
	b := p.DockerControl.OperatorBootstrap
	b.Protocol, b.Target, b.ObservationProtocol = ControlTrustBootstrapProtocol, ControlTrustTarget, ControlTrustObservationProtocol
	for i := range b.Launches {
		l := &b.Launches[i]
		if l.Target == ControlBootstrapTarget {
			l.Target = ControlTrustTarget
			l.ProbeDigest = testDigest("trust-probe")
		}
	}
	testControlTrustDirectories(&p, "")
	p.ProfileDigest = p.Digest()
	return p
}

func TestControlTrustDirectoriesBindEveryConsumerAndPreserveHolds(t *testing.T) {
	p := testControlTrust(t)
	doc, _ := json.Marshal(p)
	review, err := ReviewControlBootstrap(doc)
	if err != nil || review.Source == nil || len(review.Source.TrustAnchors) != 2 {
		t.Fatal("complete trust directory profile", err)
	}
	if _, err := ReviewControlConsumerBoundary(doc); err == nil {
		t.Fatal("v4 exchanged for old diagnostic admission description")
	}
	if p.Validate() == nil {
		t.Fatal("public hold")
	}
	if _, err := p.CodingExecutionStorageBinding(); err == nil {
		t.Fatal("Store hold")
	}
	for name, mutate := range map[string]func(*ProfileV2){
		"old target":  func(p *ProfileV2) { p.DockerControl.OperatorBootstrap.Target = ControlSourceTarget },
		"old version": func(p *ProfileV2) { p.DockerControl.OperatorBootstrap.Protocol = ControlSourceBootstrapProtocol },
		"old domain": func(p *ProfileV2) {
			p.DockerControl.OperatorBootstrap.ObservationProtocol = ControlSourceObservationProtocol
		},
		"missing directory": func(p *ProfileV2) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].MountDirectory != "" {
					p.TrustAnchors[i].MountDirectory = ""
					return
				}
			}
		},
		"broad directory": func(p *ProfileV2) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].MountDirectory != "" {
					p.TrustAnchors[i].MountDirectory = "/run/trust"
					return
				}
			}
		},
		"different file": func(p *ProfileV2) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].MountDirectory != "" {
					p.TrustAnchors[i].TargetPath += ".pem"
					return
				}
			}
		},
		"nonroot owner": func(p *ProfileV2) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].MountDirectory != "" {
					p.TrustAnchors[i].OwnerUID = 57010
					return
				}
			}
		},
		"unrelated directory": func(p *ProfileV2) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].MountDirectory == "" {
					p.TrustAnchors[i].MountDirectory = "/run/unrelated"
					return
				}
			}
		},
		"consumer file target": func(p *ProfileV2) {
			for i := range p.Principals {
				for j := range p.Principals[i].Mounts {
					m := &p.Principals[i].Mounts[j]
					if m.Target == "/run/trust/internal-client-ca" {
						m.Target += "/bundle.pem"
						return
					}
				}
			}
		},
		"consumer extra parent": func(p *ProfileV2) {
			p.Principals[0].Mounts = append(p.Principals[0].Mounts, Mount{Kind: "trust_anchor", Target: "/run/trust", StorageID: "unrelated", ReadOnly: true})
		},
		"consumer writable": func(p *ProfileV2) {
			for i := range p.Principals {
				for j := range p.Principals[i].Mounts {
					m := &p.Principals[i].Mounts[j]
					if m.Target == "/run/trust/internal-client-ca" {
						m.ReadOnly = false
						return
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var q ProfileV2
			_ = json.Unmarshal(doc, &q)
			mutate(&q)
			q.ProfileDigest = q.Digest()
			b, _ := json.Marshal(q)
			if _, err := ReviewControlBootstrap(b); err == nil {
				t.Fatal("invalid directory accepted")
			}
		})
	}
}

func TestLegacyTrustAnchorLayoutsRemainFileOnly(t *testing.T) {
	legacy := validProfile()
	if err := legacy.Validate(); err != nil {
		t.Fatal("legacy baseline", err)
	}
	a := &legacy.TrustAnchors[0]
	a.MountDirectory = "/run/trust/" + a.ID
	a.TargetPath = a.MountDirectory + "/bundle.pem"
	for i := range legacy.Principals {
		for j := range legacy.Principals[i].Mounts {
			m := &legacy.Principals[i].Mounts[j]
			if m.Kind == "trust_anchor" && m.StorageID == a.StorageID {
				m.Target = a.MountDirectory
			}
		}
	}
	legacy.ProfileDigest = legacy.Digest()
	if legacy.Validate() == nil {
		t.Fatal("v1 admitted directory layout")
	}
	p := testControlBootstrap(t)
	before, _ := json.Marshal(p)
	if bytes.Contains(before, []byte("mount_directory")) {
		t.Fatal("legacy bytes changed")
	}
	testControlTrustDirectories(&p, "")
	p.ProfileDigest = p.Digest()
	raw, _ := json.Marshal(p)
	if _, err := ReviewControlBootstrap(raw); err == nil {
		t.Fatal("legacy bootstrap accepted directory")
	}
	// Shared validation is the actual v1 entry point, including readers which
	// decode the newly known JSON field before the final Profile validation.
	var anchors []TrustAnchor
	_ = json.Unmarshal([]byte(`[{"id":"internal-client-ca","mount_directory":"/run/trust/internal-client-ca"}]`), &anchors)
	if validateTrustAnchorsWithPostgres(anchors, nil, nil, CertificateControllerAuthority{}, nil, nil, nil) == nil {
		t.Fatal("v1 directory accepted")
	}
	for _, a := range anchors {
		if validControlTrustDirectory(a, false) {
			t.Fatal("old layout accepts field")
		}
	}
}
