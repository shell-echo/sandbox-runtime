package docker

import "crypto/ed25519"

func makeBridgeVerificationKeys(values map[string][]byte) map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(values))
	for id, value := range values {
		result[id] = append(ed25519.PublicKey(nil), value...)
	}
	return result
}
