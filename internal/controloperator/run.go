package controloperator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"io"
	"reflect"
	"strings"
	"time"
)

type Result struct {
	Status              string                    `json:"status"`
	CreatedObservation  daemonObservation         `json:"created_observation"`
	LoaderObservation   daemonObservation         `json:"loader_observation"`
	FirstObservation    daemonObservation         `json:"first_observation"`
	Receipt             controldelivery.Receipt   `json:"receipt"`
	Challenge           controldelivery.Challenge `json:"challenge"`
	Reply               controldelivery.Reply     `json:"reply"`
	OperatorObservation daemonObservation         `json:"operator_observation"`
}

// Run uses an explicit private input file. It starts only the already-created
// container, after checking its complete narrow held-delivery configuration.
// The caller owns exact cleanup. No daemon defaults or environment are read.
func Run(ctx context.Context, path string) (out Result, err error) {
	out.Status = "failed"
	stage := "inputs"
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", controldelivery.ErrUnavailable, stage)
		}
	}()
	fail := controldelivery.ErrUnavailable
	if ctx == nil || ctx.Err() != nil {
		return out, fail
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	a, e := load(ctx, path)
	if e != nil {
		return out, e
	}
	defer clear(a.key)
	defer a.envelope.Destroy()
	cli, e := client.New(client.WithHost(a.input.Host), client.WithDialContext(dockerUnixDial(ctx, strings.TrimPrefix(a.input.Host, "unix://"))), client.WithAPIVersionNegotiation())
	if e != nil {
		return out, fail
	}
	defer cli.Close()
	stage = "create-observation"
	created, e := inspect(ctx, cli, a, false)
	if e != nil {
		return out, e
	}
	stage = "attach"
	out.CreatedObservation = created
	stream, e := cli.ContainerAttach(ctx, a.input.ContainerID, client.ContainerAttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	if e != nil {
		return out, fail
	}
	defer stream.Close()
	stop := context.AfterFunc(ctx, stream.Close)
	defer stop()
	deadline, _ := ctx.Deadline()
	if stream.Conn.SetDeadline(deadline) != nil {
		return out, fail
	}
	// Recheck after attach before start, so no other writer may replace inputs.
	again, e := inspect(ctx, cli, a, false)
	if e != nil || !reflect.DeepEqual(created, again) {
		return out, fail
	}
	if _, e := cli.ContainerStart(ctx, a.input.ContainerID, client.ContainerStartOptions{}); e != nil {
		return out, fail
	}
	stage = "loader"
	out.LoaderObservation, _, e = probe(ctx, cli, a, "loader")
	if e != nil {
		return out, e
	}
	stage = "envelope"
	raw, e := json.Marshal(a.envelope)
	if e != nil || phase6fdloader.WriteFrame(stream.Conn, raw, phase6fdloader.MaxEnvelopeBytes) != nil {
		clear(raw)
		return out, fail
	}
	clear(raw)
	stage = "challenge"
	stdout := &dockerStdout{r: stream.Reader}
	raw, e = phase6fdloader.ReadFrame(stdout, controldelivery.MaxFrame)
	if e != nil || len(stdout.stderr) != 0 || phase6fdloader.DecodeCanonical(raw, &out.Challenge) != nil {
		return out, fail
	}
	c := out.Challenge
	if _, e := controldelivery.ValidateChallenge(c, a.review, time.Now()); e != nil || c.Startup.ContainerID != a.input.ContainerID || c.Startup.RunID != a.envelope.RunID || c.Startup.Nonce != a.envelope.Nonce {
		return out, fail
	}
	stage = "first-observation"
	first, e := observe(ctx, cli, a, c)
	if e != nil {
		return out, e
	}
	out.FirstObservation = first
	stage = "second-observation"
	second, e := observe(ctx, cli, a, c)
	out.OperatorObservation = second
	if e != nil || !reflect.DeepEqual(first, second) || first.Created != created.Created || !reflect.DeepEqual(first.Config, created.Config) || !reflect.DeepEqual(first.HostConfig, created.HostConfig) || !reflect.DeepEqual(first.Mounts, created.Mounts) {
		return out, fail
	}
	if _, e := controldelivery.ValidateChallenge(c, a.review, time.Now()); e != nil || ctx.Err() != nil {
		return out, fail
	}
	stage = "signature"
	out.OperatorObservation = second
	out.Reply = controldelivery.Reply{Protocol: c.Protocol, Scope: c.Scope, ChallengeDigest: controldelivery.Digest(raw), OperatorObservationDigest: observationDigest(second)}
	signed, e := controldelivery.SigningBytes(c, out.Reply)
	if e != nil {
		return out, e
	}
	out.Reply.Signature = ed25519.Sign(a.key, signed)
	raw, e = json.Marshal(out.Reply)
	if e != nil || phase6fdloader.WriteFrame(stream.Conn, raw, controldelivery.MaxFrame) != nil {
		return out, fail
	}
	cw, ok := stream.Conn.(client.CloseWriter)
	if !ok || cw.CloseWrite() != nil {
		return out, fail
	}
	stage = "receipt"
	raw, e = phase6fdloader.ReadFrame(stdout, controldelivery.MaxFrame)
	if e != nil || phase6fdloader.DecodeCanonical(raw, &out.Receipt) != nil {
		return out, fail
	}
	want := controldelivery.Receipt{Protocol: c.Protocol, Scope: c.Scope, Admission: "held-not-a-permit", ChallengeDigest: out.Reply.ChallengeDigest, OperatorObservationDigest: out.Reply.OperatorObservationDigest}
	if out.Receipt != want {
		return out, fail
	}
	tail, e := io.ReadAll(io.LimitReader(stdout, 1))
	if e != nil || len(tail) != 0 || string(stdout.stderr) != "private Control failed\n" {
		return out, fail
	}
	exit, e := cli.ContainerInspect(ctx, a.input.ContainerID, client.ContainerInspectOptions{})
	if e != nil || exit.Container.State == nil || exit.Container.State.Running || exit.Container.State.ExitCode != 1 || exit.Container.State.OOMKilled || exit.Container.RestartCount != 0 || ctx.Err() != nil {
		return out, fail
	}
	out.Status = "verified-held"
	return out, nil
}
