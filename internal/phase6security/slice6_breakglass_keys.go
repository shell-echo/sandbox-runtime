package phase6security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// Slice6DesiredCredentialKeyIDs is independent of any already-frozen Profile.
// The same source private key must supply a credential-controller client, its
// material-agent FD and, for the seven nonmigration agents only, a break-glass
// target actor. This eliminates the previous compose-after-key cycle.
func Slice6DesiredCredentialKeyIDs() []string {
	result := []string{"credential-certificate-controller"}
	for _, template := range slice6MaterialAccessTemplates {
		result = append(result, "credential-"+template.agent)
	}
	slices.Sort(result)
	return result
}

func Slice6DesiredBreakGlassIndependentKeyIDs() []string {
	return []string{"break-glass-approver-a", "break-glass-approver-b", "break-glass-controller-signer",
		"break-glass-operator-a", "break-glass-requester-a"}
}

type Slice6BreakGlassActorKey struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Owner           string `json:"owner"`
	KeyID           string `json:"key_id"`
	PublicKeyDigest string `json:"public_key_digest"`
}

type Slice6BreakGlassKeyAuthority struct {
	Actors                    []Slice6BreakGlassActorKey `json:"actors"`
	ControllerKeyID           string                     `json:"controller_key_id"`
	ControllerPublicKeyDigest string                     `json:"controller_public_key_digest"`
}

func Slice6BreakGlassPublicKeyDigest(public ed25519.PublicKey) string {
	if len(public) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-break-glass/public-key/v1\x00"), public...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildSlice6BreakGlassKeyAuthority is a pure projection of five independent
// public sources and the pre-existing 12 credential identities. It never
// receives requester/approver/operator private keys or invents target keys.
func BuildSlice6BreakGlassKeyAuthority(independent, credential map[string]ed25519.PublicKey) (Slice6BreakGlassKeyAuthority, error) {
	independentIDs, credentialIDs := Slice6DesiredBreakGlassIndependentKeyIDs(), Slice6DesiredCredentialKeyIDs()
	if len(independent) != len(independentIDs) || len(credential) != len(credentialIDs) ||
		len(independentIDs) != 5 || len(credentialIDs) != 12 {
		return Slice6BreakGlassKeyAuthority{}, errSlice6DesiredInventory
	}
	seenKey := make(map[string]bool, len(independent)+len(credential))
	for _, set := range []struct {
		ids  []string
		keys map[string]ed25519.PublicKey
	}{{independentIDs, independent}, {credentialIDs, credential}} {
		for _, id := range set.ids {
			key, exists := set.keys[id]
			if !exists || len(key) != ed25519.PublicKeySize || seenKey[string(key)] {
				return Slice6BreakGlassKeyAuthority{}, errSlice6DesiredInventory
			}
			seenKey[string(key)] = true
		}
	}
	result := Slice6BreakGlassKeyAuthority{ControllerKeyID: "break-glass-controller-signer",
		ControllerPublicKeyDigest: Slice6BreakGlassPublicKeyDigest(independent["break-glass-controller-signer"])}
	for _, spec := range []struct{ id, kind string }{
		{"approver-a", "approver"}, {"approver-b", "approver"}, {"operator-a", "operator"}, {"requester-a", "requester"},
	} {
		keyID := "break-glass-" + spec.id
		result.Actors = append(result.Actors, Slice6BreakGlassActorKey{ID: spec.id, Kind: spec.kind,
			Owner: keyID, KeyID: keyID, PublicKeyDigest: Slice6BreakGlassPublicKeyDigest(independent[keyID])})
	}
	runtimeAgents := 0
	for _, template := range slice6MaterialAccessTemplates {
		if template.owner == "product-migration-job" || template.owner == "provider-migration-job" ||
			template.owner == "provider-browser-migration-job" || template.owner == "provider-desktop-migration-job" {
			continue
		}
		keyID := "credential-" + template.agent
		result.Actors = append(result.Actors, Slice6BreakGlassActorKey{ID: template.agent, Kind: "target",
			Owner: template.agent, KeyID: keyID,
			PublicKeyDigest: Slice6BreakGlassPublicKeyDigest(credential[keyID])})
		runtimeAgents++
	}
	if runtimeAgents != 7 || len(result.Actors) != 11 || result.ControllerPublicKeyDigest == "" {
		return Slice6BreakGlassKeyAuthority{}, errSlice6DesiredInventory
	}
	slices.SortFunc(result.Actors, func(a, b Slice6BreakGlassActorKey) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	if VerifySlice6BreakGlassKeyAuthority(result) != nil {
		return Slice6BreakGlassKeyAuthority{}, errSlice6DesiredInventory
	}
	return result, nil
}

// VerifySlice6BreakGlassKeyAuthority closes the actor inventory, identity
// ownership and digest shape. Source possession and target/credential key
// equality are separately established by the source-bound profile builder.
func VerifySlice6BreakGlassKeyAuthority(authority Slice6BreakGlassKeyAuthority) error {
	if authority.ControllerKeyID != "break-glass-controller-signer" ||
		!digestPattern.MatchString(authority.ControllerPublicKeyDigest) || len(authority.Actors) != 11 {
		return errSlice6DesiredInventory
	}
	want := make([]Slice6BreakGlassActorKey, 0, 11)
	for _, spec := range []struct{ id, kind string }{
		{"approver-a", "approver"}, {"approver-b", "approver"}, {"operator-a", "operator"}, {"requester-a", "requester"},
	} {
		keyID := "break-glass-" + spec.id
		want = append(want, Slice6BreakGlassActorKey{ID: spec.id, Kind: spec.kind, Owner: keyID, KeyID: keyID})
	}
	for _, template := range slice6MaterialAccessTemplates {
		if template.owner == "product-migration-job" || template.owner == "provider-migration-job" ||
			template.owner == "provider-browser-migration-job" || template.owner == "provider-desktop-migration-job" {
			continue
		}
		want = append(want, Slice6BreakGlassActorKey{ID: template.agent, Kind: "target", Owner: template.agent,
			KeyID: "credential-" + template.agent})
	}
	slices.SortFunc(want, func(a, b Slice6BreakGlassActorKey) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	if len(want) != len(authority.Actors) {
		return errSlice6DesiredInventory
	}
	seenDigests := map[string]bool{authority.ControllerPublicKeyDigest: true}
	for i, actor := range authority.Actors {
		if actor.ID != want[i].ID || actor.Kind != want[i].Kind || actor.Owner != want[i].Owner ||
			actor.KeyID != want[i].KeyID || !digestPattern.MatchString(actor.PublicKeyDigest) ||
			seenDigests[actor.PublicKeyDigest] {
			return errSlice6DesiredInventory
		}
		seenDigests[actor.PublicKeyDigest] = true
	}
	return nil
}
