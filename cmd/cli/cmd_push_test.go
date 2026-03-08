package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

func TestBuildPushRequest_BasicFields(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	fp := crypto.ComputeFingerprint([]byte(pubKey))

	bundle := &crypto.EncryptedBundle{
		Ciphertext: []byte("ct"),
		Nonce:      []byte("nonce123456"),
		AuthTag:    []byte("authtag12345678"),
		Checksum:   "abc123",
		Recipients: []crypto.EncryptedRecipient{
			{
				KeyFingerprint:  fp,
				EncryptedAESKey: []byte("enckey"),
				EphemeralPublic: []byte("ephpub"),
				KeyNonce:        []byte("knonce"),
				KeyAuthTag:      []byte("ktag"),
			},
		},
	}

	req := buildPushRequest("project-id", "production", bundle, "test push")

	if req["project_id"] != "project-id" {
		t.Errorf("unexpected project_id: %v", req["project_id"])
	}
	if req["environment"] != "production" {
		t.Errorf("unexpected environment: %v", req["environment"])
	}
	if req["message"] != "test push" {
		t.Errorf("unexpected message: %v", req["message"])
	}
	if req["checksum"] != "abc123" {
		t.Errorf("unexpected checksum: %v", req["checksum"])
	}

	// Verify ciphertext is base64-encoded.
	ctB64, ok := req["ciphertext"].(string)
	if !ok {
		t.Fatal("ciphertext should be a string")
	}
	decoded, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("ciphertext is not valid base64: %v", err)
	}
	if string(decoded) != "ct" {
		t.Errorf("unexpected ciphertext decoded value: %q", decoded)
	}

	// Verify recipients slice.
	recipients, ok := req["recipients"].([]map[string]any)
	if !ok {
		t.Fatal("recipients should be []map[string]any")
	}
	if len(recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(recipients))
	}
	rec := recipients[0]
	if rec["key_fingerprint"] != fp {
		t.Errorf("unexpected fingerprint: %v", rec["key_fingerprint"])
	}
	if _, hasEph := rec["ephemeral_public"]; !hasEph {
		t.Error("ephemeral_public should be present for ed25519 recipient")
	}
}

func TestBuildPushRequest_NoMessage(t *testing.T) {
	bundle := &crypto.EncryptedBundle{
		Ciphertext: []byte("ct"),
		Nonce:      []byte("nonce"),
		AuthTag:    []byte("tag"),
		Checksum:   "sum",
		Recipients: []crypto.EncryptedRecipient{},
	}
	req := buildPushRequest("pid", "dev", bundle, "")
	if _, ok := req["message"]; ok {
		t.Error("message should not be present when empty")
	}
}

func TestBuildPushRequest_RSARecipient(t *testing.T) {
	// RSA recipient has no EphemeralPublic — only EncryptedAESKey.
	bundle := &crypto.EncryptedBundle{
		Ciphertext: []byte("ct"),
		Nonce:      []byte("nonce"),
		AuthTag:    []byte("tag"),
		Checksum:   "sum",
		Recipients: []crypto.EncryptedRecipient{
			{
				KeyFingerprint:  "rsa-fp",
				EncryptedAESKey: []byte("rsaenc"),
				// No EphemeralPublic for RSA.
			},
		},
	}
	req := buildPushRequest("pid", "dev", bundle, "")
	recipients := req["recipients"].([]map[string]any)
	rec := recipients[0]
	if _, hasEph := rec["ephemeral_public"]; hasEph {
		t.Error("ephemeral_public should not be present for RSA recipient")
	}
}
