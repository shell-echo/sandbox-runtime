// Package restricted defines the sealed Provider-local identity and policy
// shared by restricted-egress network implementations. It is not a wire API.
package restricted

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

const (
	ManagedLabel            = "io.github.shell-echo.sandbox-runtime.managed"
	OwnerLabel              = "io.github.shell-echo.sandbox-runtime.owner"
	NamespaceLabel          = "io.github.shell-echo.sandbox-runtime.namespace"
	ControllerLabel         = "io.github.shell-echo.sandbox-runtime.controller-id"
	SandboxLabel            = "io.github.shell-echo.sandbox-runtime.provider-sandbox-id"
	BrowserSessionLabel     = "io.github.shell-echo.sandbox-runtime.browser-session-id"
	DesktopSessionLabel     = "io.github.shell-echo.sandbox-runtime.desktop-session-id"
	RuntimeProfileLabel     = "io.github.shell-echo.sandbox-runtime.runtime-profile"
	WorkloadRoleLabel       = "io.github.shell-echo.sandbox-runtime.restricted-workload-role"
	WorkloadIdentityLabel   = "io.github.shell-echo.sandbox-runtime.restricted-workload-identity"
	WorkloadGenerationLabel = "io.github.shell-echo.sandbox-runtime.restricted-workload-generation"
	WorkloadFenceLabel      = "io.github.shell-echo.sandbox-runtime.restricted-workload-fence"
	WorkloadLeaseLabel      = "io.github.shell-echo.sandbox-runtime.restricted-network-lease"
)

var (
	ErrInvalidIdentity = errors.New("invalid restricted-egress workload identity")
	identifierPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

type workloadRole uint8

const (
	roleBrowser workloadRole = iota + 1
	roleDesktop
)

// Identity is deliberately sealed: callers can construct only Browser or
// Desktop identities and cannot inject a role, workload name, owner, session
// label, or runtime profile.
type Identity struct {
	role       workloadRole
	namespace  string
	controller string
	sandbox    string
	session    string
	generation int64
	fence      int64
}

func BrowserIdentity(namespace, controller, sandbox, session string, generation, fence int64) (Identity, error) {
	return newIdentity(roleBrowser, namespace, controller, sandbox, session, generation, fence)
}

func DesktopIdentity(namespace, controller, sandbox, session string, generation, fence int64) (Identity, error) {
	return newIdentity(roleDesktop, namespace, controller, sandbox, session, generation, fence)
}

func newIdentity(role workloadRole, namespace, controller, sandbox, session string, generation, fence int64) (Identity, error) {
	identity := Identity{role: role, namespace: namespace, controller: controller, sandbox: sandbox, session: session, generation: generation, fence: fence}
	if identity.Validate() != nil {
		return Identity{}, ErrInvalidIdentity
	}
	return identity, nil
}

func (i Identity) Validate() error {
	if i.role != roleBrowser && i.role != roleDesktop || i.generation < 1 || i.fence < 1 {
		return ErrInvalidIdentity
	}
	for _, value := range []string{i.namespace, i.controller, i.sandbox, i.session} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidIdentity
		}
	}
	return nil
}

func (i Identity) Role() string {
	if i.role == roleBrowser {
		return "browser"
	}
	if i.role == roleDesktop {
		return "desktop"
	}
	return ""
}

func (i Identity) Namespace() string  { return i.namespace }
func (i Identity) Controller() string { return i.controller }
func (i Identity) Sandbox() string    { return i.sandbox }
func (i Identity) Session() string    { return i.session }
func (i Identity) Generation() int64  { return i.generation }
func (i Identity) Fence() int64       { return i.fence }

func (i Identity) WorkloadName() string {
	if i.Validate() != nil {
		return ""
	}
	digest := sha256.Sum256([]byte(i.sandbox + "\x00" + i.session))
	return "sandbox-runtime-" + i.Role() + "-" + hex.EncodeToString(digest[:16])
}

func (i Identity) SessionLabel() string {
	if i.role == roleBrowser {
		return BrowserSessionLabel
	}
	if i.role == roleDesktop {
		return DesktopSessionLabel
	}
	return ""
}

func (i Identity) Owner() string {
	if i.role == roleBrowser {
		return "provider-browser-runtime"
	}
	if i.role == roleDesktop {
		return "provider-desktop-runtime"
	}
	return ""
}

func (i Identity) RuntimeProfile() string {
	if i.role == roleBrowser {
		return "sandbox-runtime-browser-v1"
	}
	if i.role == roleDesktop {
		return "sandbox-runtime-desktop-v1"
	}
	return ""
}

func (i Identity) NetworkPrefix() string {
	if i.role == roleBrowser {
		return "sandbox-runtime-browser-egress-"
	}
	if i.role == roleDesktop {
		return "sandbox-runtime-desktop-egress-"
	}
	return ""
}

func (i Identity) GatewayPrefix() string {
	if i.role == roleBrowser {
		return "sandbox-runtime-browser-gateway-"
	}
	if i.role == roleDesktop {
		return "sandbox-runtime-desktop-gateway-"
	}
	return ""
}

func (i Identity) LeasePrefix() string {
	if i.role == roleBrowser {
		return "browser-egress-"
	}
	if i.role == roleDesktop {
		return "desktop-egress-"
	}
	return ""
}

func (i Identity) Digest() string {
	if i.Validate() != nil {
		return ""
	}
	value := struct {
		Domain     string `json:"domain"`
		Role       string `json:"role"`
		Namespace  string `json:"namespace"`
		Controller string `json:"controller_id"`
		Sandbox    string `json:"sandbox_id"`
		Session    string `json:"session_id"`
		Generation int64  `json:"generation"`
		Fence      int64  `json:"fence"`
	}{"sandbox-runtime/restricted-workload-identity/v1", i.Role(), i.namespace, i.controller, i.sandbox, i.session, i.generation, i.fence}
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (i Identity) WorkloadLabels(lease string) map[string]string {
	if i.Validate() != nil || !identifierPattern.MatchString(lease) {
		return nil
	}
	return map[string]string{
		ManagedLabel:            "true",
		OwnerLabel:              i.Owner(),
		NamespaceLabel:          i.namespace,
		ControllerLabel:         i.controller,
		SandboxLabel:            i.sandbox,
		i.SessionLabel():        i.session,
		RuntimeProfileLabel:     i.RuntimeProfile(),
		WorkloadRoleLabel:       i.Role(),
		WorkloadIdentityLabel:   i.Digest(),
		WorkloadGenerationLabel: strconv.FormatInt(i.generation, 10),
		WorkloadFenceLabel:      strconv.FormatInt(i.fence, 10),
		WorkloadLeaseLabel:      lease,
	}
}
