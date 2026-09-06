//go:build darwin || linux

package orchestrator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/provisioning"
)

const (
	maxDownstreamControlRecordBytes = 96 << 10
	downstreamProcessReapTimeout    = 3 * time.Second
)

var errDownstreamCallerProcess = errors.New("downstream-fencing caller process failed")

// downstreamCallerProcess owns one caller child and its one-shot provisioning
// state. Any ambiguous pipe operation permanently terminates the process.
type downstreamCallerProcess struct {
	command    *exec.Cmd
	input      io.WriteCloser
	output     *bufio.Scanner
	outputFile io.ReadCloser
	final      *os.File
	log        *os.File
	done       chan struct{}

	requestMu sync.Mutex
	ioMu      sync.Mutex
	stateMu   sync.Mutex
	stopOnce  sync.Once
	closeOnce sync.Once
	requestID string
	endpoint  provisioning.EndpointEnvelope
	sequence  uint64
	committed bool
	err       error
}

func startDownstreamCaller(
	ctx context.Context,
	binary, bootstrapConfigPath, providerBootstrapConfigPath, logPath string,
	request provisioning.Request,
) (*downstreamCallerProcess, provisioning.EndpointEnvelope, error) {
	return startDownstreamCallerCommand(ctx, binary, []string{
		"-config", bootstrapConfigPath,
		"-provider-bootstrap-config", providerBootstrapConfigPath,
	}, logPath, request)
}

func startDownstreamCallerCommand(
	ctx context.Context,
	binary string,
	arguments []string,
	logPath string,
	request provisioning.Request,
) (*downstreamCallerProcess, provisioning.EndpointEnvelope, error) {
	if ctx == nil || binary == "" || logPath == "" {
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}

	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		_ = logFile.Close()
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	endpointRead, endpointWrite, err := os.Pipe()
	if err != nil {
		closeFiles(requestRead, requestWrite, logFile)
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	finalRead, finalWrite, err := os.Pipe()
	if err != nil {
		closeFiles(requestRead, requestWrite, endpointRead, endpointWrite, logFile)
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}

	command := exec.Command(binary, arguments...)
	input, err := command.StdinPipe()
	if err != nil {
		closeFiles(requestRead, requestWrite, endpointRead, endpointWrite, finalRead, finalWrite, logFile)
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	outputFile, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		closeFiles(requestRead, requestWrite, endpointRead, endpointWrite, finalRead, finalWrite, logFile)
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	command.Stderr = logFile
	command.ExtraFiles = []*os.File{requestRead, endpointWrite, finalRead}
	process := &downstreamCallerProcess{
		command: command, input: input, outputFile: outputFile, final: finalWrite, log: logFile,
		done: make(chan struct{}), requestID: request.RequestID,
	}
	process.output = bufio.NewScanner(outputFile)
	process.output.Buffer(make([]byte, 4096), maxDownstreamControlRecordBytes)

	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = outputFile.Close()
		closeFiles(requestRead, requestWrite, endpointRead, endpointWrite, finalRead, finalWrite, logFile)
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	go func() {
		err := command.Wait()
		process.stateMu.Lock()
		process.err = err
		process.stateMu.Unlock()
		_ = logFile.Close()
		process.closeParentIO()
		close(process.done)
	}()

	// ExtraFiles duplicates these descriptors into child FDs 3, 4, and 5.
	// Keeping the parent copies open would suppress the EOF that delimits each
	// one-shot record.
	childCloseErr := errors.Join(requestRead.Close(), endpointWrite.Close(), finalRead.Close())
	if childCloseErr != nil {
		closeFiles(requestWrite, endpointRead)
		_ = process.failAndReap()
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}

	if err := process.runProvisioningPhase(ctx, requestWrite, func() error {
		return provisioning.WriteRequest(requestWrite, request)
	}); err != nil {
		closeFiles(endpointRead)
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}

	var endpoint provisioning.EndpointEnvelope
	if err := process.runProvisioningPhase(ctx, endpointRead, func() error {
		var readErr error
		endpoint, readErr = provisioning.ReadEndpoint(endpointRead)
		return readErr
	}); err != nil || !downstreamEndpointMatchesRequest(endpoint, request, time.Now().UTC()) {
		_ = process.failAndReap()
		return nil, provisioning.EndpointEnvelope{}, errDownstreamCallerProcess
	}
	process.endpoint = endpoint
	return process, endpoint, nil
}

func downstreamEndpointMatchesRequest(endpoint provisioning.EndpointEnvelope, request provisioning.Request, now time.Time) bool {
	return endpoint.Version == provisioning.ProtocolVersion && endpoint.RequestID == request.RequestID &&
		endpoint.Endpoint.TenantID == request.TenantID && endpoint.Endpoint.SandboxID == request.SandboxID &&
		endpoint.Endpoint.BrowserSessionID == request.BrowserSessionID &&
		endpoint.Endpoint.CapabilityProfileID == request.CapabilityProfileID && downstreamEndpointIsFresh(endpoint, now)
}

func downstreamEndpointIsFresh(endpoint provisioning.EndpointEnvelope, now time.Time) bool {
	grantExpiry, grantErr := time.Parse(time.RFC3339Nano, endpoint.GrantBinding.ExpiresAt)
	handoffExpiry, handoffErr := time.Parse(time.RFC3339Nano, endpoint.HandoffExpiresAt)
	return grantErr == nil && handoffErr == nil && grantExpiry.After(now) && handoffExpiry.After(now) &&
		!grantExpiry.After(handoffExpiry)
}

// commit delivers the exact final configuration once. The FD protocol has no
// acknowledgement, so acceptance is established only by a later correlated
// JSONL response from the child.
func (p *downstreamCallerProcess) commit(
	ctx context.Context,
	config downstreamcaller.Config,
) error {
	if p == nil || ctx == nil {
		return errDownstreamCallerProcess
	}
	p.requestMu.Lock()
	defer p.requestMu.Unlock()
	final := p.finalFile()
	if p.committed || final == nil || p.endpoint.RequestID != p.requestID || !downstreamEndpointIsFresh(p.endpoint, time.Now().UTC()) ||
		!downstreamConfigMatchesEndpoint(config, p.endpoint) {
		return p.failAndReap()
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return p.failAndReap()
	}
	frame := provisioning.FinalConfiguration{
		Version: provisioning.ProtocolVersion, RequestID: p.requestID, Config: encoded,
	}
	if err := p.runProvisioningPhase(ctx, final, func() error {
		return provisioning.WriteFinalConfiguration(final, frame)
	}); err != nil {
		return errDownstreamCallerProcess
	}
	p.clearFinalFile(final)
	p.committed = true
	select {
	case <-p.done:
		return p.failAndReap()
	default:
		return nil
	}
}

func downstreamConfigMatchesEndpoint(config downstreamcaller.Config, envelope provisioning.EndpointEnvelope) bool {
	if len(config.Principals) != 1 || len(config.Endpoints) != 1 || len(config.GrantBindings) != 1 {
		return false
	}
	endpoint := config.Endpoints[0]
	grant := config.GrantBindings[0]
	principal := config.Principals[0]
	return endpoint.ID == envelope.Endpoint.ID && endpoint.TenantID == envelope.Endpoint.TenantID &&
		endpoint.SandboxID == envelope.Endpoint.SandboxID && endpoint.BrowserSessionID == envelope.Endpoint.BrowserSessionID &&
		endpoint.CapabilityProfileID == envelope.Endpoint.CapabilityProfileID &&
		endpoint.HandoffReference == envelope.Endpoint.HandoffReference &&
		endpoint.ConnectionGeneration == envelope.Endpoint.ConnectionGeneration &&
		grant.ID == envelope.GrantBinding.ID && grant.GrantID == envelope.GrantBinding.GrantID &&
		grant.PrincipalID == envelope.GrantBinding.PrincipalID && grant.EndpointID == envelope.GrantBinding.EndpointID &&
		grant.ExpiresAt == envelope.GrantBinding.ExpiresAt && principal.ID == grant.PrincipalID &&
		principal.TenantID == endpoint.TenantID
}

func (p *downstreamCallerProcess) request(ctx context.Context, command downstreamcaller.Command) (downstreamcaller.Response, error) {
	if p == nil || ctx == nil {
		return downstreamcaller.Response{}, errDownstreamCallerProcess
	}
	p.requestMu.Lock()
	defer p.requestMu.Unlock()
	if !p.committed {
		_ = p.failAndReap()
		return downstreamcaller.Response{}, errDownstreamCallerProcess
	}
	select {
	case <-p.done:
		return downstreamcaller.Response{}, p.failAndReap()
	default:
	}
	input, output := p.controlIO()
	if input == nil || output == nil {
		return downstreamcaller.Response{}, p.failAndReap()
	}
	p.sequence++
	command.Version = downstreamcaller.ProtocolVersion
	command.Sequence = p.sequence
	encoded, err := json.Marshal(command)
	if err != nil || len(encoded)+1 > maxDownstreamControlRecordBytes {
		_ = p.failAndReap()
		return downstreamcaller.Response{}, errDownstreamCallerProcess
	}
	encoded = append(encoded, '\n')

	type operationResult struct {
		response downstreamcaller.Response
		err      error
	}
	result := make(chan operationResult, 1)
	go func() {
		if writeAll(input, encoded) != nil || !output.Scan() {
			result <- operationResult{err: errDownstreamCallerProcess}
			return
		}
		response, err := decodeDownstreamResponse(output.Bytes())
		result <- operationResult{response: response, err: err}
	}()
	select {
	case completed := <-result:
		if completed.err != nil || completed.response.Version != downstreamcaller.ProtocolVersion ||
			completed.response.Sequence != command.Sequence {
			_ = p.failAndReap()
			return downstreamcaller.Response{}, errDownstreamCallerProcess
		}
		return completed.response, nil
	case <-ctx.Done():
		_ = p.failAndReap()
		return downstreamcaller.Response{}, errDownstreamCallerProcess
	case <-p.done:
		return downstreamcaller.Response{}, p.failAndReap()
	}
}

func decodeDownstreamResponse(content []byte) (downstreamcaller.Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var response downstreamcaller.Response
	if err := decoder.Decode(&response); err != nil {
		return downstreamcaller.Response{}, errDownstreamCallerProcess
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return downstreamcaller.Response{}, errDownstreamCallerProcess
	}
	return response, nil
}

func (p *downstreamCallerProcess) shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		p.closeParentIO()
		if p.result() != nil {
			return errDownstreamCallerProcess
		}
		return nil
	default:
	}
	response, err := p.request(ctx, downstreamcaller.Command{Action: downstreamcaller.ActionShutdown})
	if err != nil || !response.OK || response.Outcome != downstreamcaller.OutcomeTerminated || response.ErrorCode != "" {
		return p.failAndReap()
	}
	input, _ := p.controlIO()
	if input != nil {
		_ = input.Close()
	}
	if !waitForDownstreamProcess(p.done, ctx, downstreamProcessReapTimeout) || p.result() != nil {
		return p.failAndReap()
	}
	p.closeParentIO()
	return nil
}

func (p *downstreamCallerProcess) runProvisioningPhase(ctx context.Context, file *os.File, operation func() error) error {
	if p == nil || ctx == nil || file == nil || operation == nil {
		return errDownstreamCallerProcess
	}
	result := make(chan error, 1)
	go func() { result <- operation() }()
	select {
	case err := <-result:
		if closeErr := file.Close(); err != nil || closeErr != nil {
			return p.failAndReap()
		}
		return nil
	case <-ctx.Done():
		_ = file.Close()
		failure := p.failAndReap()
		waitForProvisioningOperation(result)
		return failure
	case <-p.done:
		_ = file.Close()
		failure := p.failAndReap()
		waitForProvisioningOperation(result)
		return failure
	}
}

func (p *downstreamCallerProcess) failAndReap() error {
	if p == nil {
		return errDownstreamCallerProcess
	}
	p.stopOnce.Do(func() {
		p.closeParentIO()
		if p.command != nil && p.command.Process != nil {
			_ = p.command.Process.Kill()
		}
	})
	_ = waitForDownstreamProcess(p.done, context.Background(), downstreamProcessReapTimeout)
	return errDownstreamCallerProcess
}

func (p *downstreamCallerProcess) closeParentIO() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		p.ioMu.Lock()
		defer p.ioMu.Unlock()
		if p.final != nil {
			_ = p.final.Close()
			p.final = nil
		}
		if p.input != nil {
			_ = p.input.Close()
			p.input = nil
		}
		if p.outputFile != nil {
			_ = p.outputFile.Close()
			p.outputFile = nil
		}
	})
}

func (p *downstreamCallerProcess) finalFile() *os.File {
	p.ioMu.Lock()
	defer p.ioMu.Unlock()
	return p.final
}

func (p *downstreamCallerProcess) clearFinalFile(final *os.File) {
	p.ioMu.Lock()
	defer p.ioMu.Unlock()
	if p.final == final {
		p.final = nil
	}
}

func (p *downstreamCallerProcess) controlIO() (io.WriteCloser, *bufio.Scanner) {
	p.ioMu.Lock()
	defer p.ioMu.Unlock()
	if p.input == nil || p.outputFile == nil {
		return nil, nil
	}
	return p.input, p.output
}

func waitForProvisioningOperation(result <-chan error) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-result:
	case <-timer.C:
	}
}

func (p *downstreamCallerProcess) result() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.err
}

func waitForDownstreamProcess(done <-chan struct{}, ctx context.Context, maximum time.Duration) bool {
	if done == nil || ctx == nil || maximum <= 0 {
		return false
	}
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil || written <= 0 || written > len(content) {
			return errDownstreamCallerProcess
		}
		content = content[written:]
	}
	return nil
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
