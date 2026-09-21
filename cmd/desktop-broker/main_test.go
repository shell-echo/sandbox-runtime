package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
)

func TestBridgeAuthorityRequiresExplicitSessionProtocol(t *testing.T) {
	key := make([]byte, ed25519.PublicKeySize)
	for index := range key {
		key[index] = byte(index + 1)
	}
	validV2 := map[string]string{
		desktopbroker.SessionProtocolEnv:            desktopbroker.SessionProtocolV2ID,
		"SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY": base64.RawStdEncoding.EncodeToString(key),
		"SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID":     "provider-desktop-v2",
	}
	for name, environment := range map[string]map[string]string{
		"missing protocol": {},
		"unknown protocol": {desktopbroker.SessionProtocolEnv: "desktop-session.latest"},
		"v2 missing key":   {desktopbroker.SessionProtocolEnv: desktopbroker.SessionProtocolV2ID},
		"v1 with key": {desktopbroker.SessionProtocolEnv: desktopbroker.SessionProtocolID,
			"SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY": validV2["SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY"]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := bridgeAuthority(func(name string) string { return environment[name] }); err == nil {
				t.Fatal("unsafe Desktop session mode was accepted")
			}
		})
	}
	protocol, keys, err := bridgeAuthority(func(name string) string { return validV2[name] })
	if err != nil || protocol != desktopbroker.SessionProtocolV2ID || len(keys) != 1 {
		t.Fatalf("v2 authority protocol=%q keys=%d err=%v", protocol, len(keys), err)
	}
	legacy := map[string]string{desktopbroker.SessionProtocolEnv: desktopbroker.SessionProtocolID}
	protocol, keys, err = bridgeAuthority(func(name string) string { return legacy[name] })
	if err != nil || protocol != desktopbroker.SessionProtocolID || keys != nil {
		t.Fatalf("v1 compatibility protocol=%q keys=%d err=%v", protocol, len(keys), err)
	}
}
