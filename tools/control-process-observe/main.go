// control-process-observe runs inside an explicitly selected container only
// as an operator probe. Its output is private evidence, never a signed permit.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"io"
	"os"
	"time"
)

func run() error {
	if len(os.Args) != 3 && len(os.Args) != 6 {
		return phase6process.ErrIdentity
	}
	data, e := io.ReadAll(io.LimitReader(os.Stdin, (4<<20)+1))
	if e != nil || len(data) > 4<<20 {
		return phase6process.ErrIdentity
	}
	defer clear(data)
	r, e := phase6security.ReviewControlBootstrap(data)
	if e != nil {
		return phase6process.ErrIdentity
	}
	var selected *phase6security.ControlServiceIdentityV1
	for i := range r.Services {
		if r.Services[i].Principal.Name == os.Args[1] {
			selected = &r.Services[i]
		}
	}
	if selected == nil || (phase6security.ControlObservesSource(selected.Launch.Target)) != (len(os.Args) == 6) {
		return phase6process.ErrIdentity
	}
	budget := 5 * time.Second
	if phase6security.ControlObservesSource(selected.Launch.Target) {
		budget = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	o, e := phase6process.ObservePID1(ctx)
	if e != nil || phase6process.Verify(o, *selected, os.Args[2]) != nil {
		return phase6process.ErrIdentity
	}
	var probe *phase6process.ProbeObservation
	if selected.Launch.Target == phase6security.ControlDeliveryTarget || phase6security.ControlObservesSource(selected.Launch.Target) {
		p, e := phase6process.ObserveProbe(ctx, selected.Launch.ProbeDigest, true)
		if e != nil {
			return e
		}
		probe = &p
	}
	var source *phase6process.SourceObservation
	if phase6security.ControlObservesSource(selected.Launch.Target) && os.Args[2] == "role" {
		startup := phase6fdloader.StartupBinding{Protocol: phase6fdloader.ControlStartupProtocol(selected.Launch.Target), RunID: os.Args[3], Nonce: os.Args[4], ContainerID: os.Args[5], Target: selected.Launch.Target}
		session, err := dockercontrol.PrepareControlSource(ctx, data, startup)
		if err != nil {
			return err
		}
		defer session.Close()
		v, err := session.Observe(ctx)
		if err != nil {
			return err
		}
		source = &v
	}
	return json.NewEncoder(os.Stdout).Encode(phase6process.ProbeReport{Admission: "held-not-a-permit", ProfileBytesDigest: r.ProfileBytesDigest, Deployment: selected.Principal.Name, Stage: os.Args[2], Observation: o, Probe: probe, Source: source})
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "service process identity unavailable")
		os.Exit(1)
	}
}
