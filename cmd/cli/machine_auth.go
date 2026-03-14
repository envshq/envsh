package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

// getMachineToken performs machine challenge-response auth and returns a JWT.
//
// Flow:
//  1. Parse ENVSH_MACHINE_KEY → Ed25519 seed
//  2. Derive public key → compute fingerprint
//  3. POST /auth/machine-challenge {fingerprint} → nonce + machine_id
//  4. Sign nonce with Ed25519 private key
//  5. POST /auth/machine-verify {machine_id, nonce, signature} → JWT
func getMachineToken(machineKey string) (string, error) {
	// 1. Parse key
	seed, err := crypto.ParseMachineKey(machineKey)
	if err != nil {
		return "", fmt.Errorf("parsing machine key: %w", err)
	}
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	fingerprint := crypto.ComputeFingerprint([]byte(pubKey))

	// 2. Request challenge
	resp, err := apiRequest("POST", "/auth/machine-challenge", map[string]string{
		"fingerprint": fingerprint,
	}, "")
	if err != nil {
		return "", fmt.Errorf("requesting machine challenge: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return "", fmt.Errorf("machine challenge failed: %w", err)
	}

	var challengeResp struct {
		Nonce     string `json:"nonce"`
		MachineID string `json:"machine_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		return "", fmt.Errorf("decoding challenge response: %w", err)
	}

	// 3. Sign the nonce (raw bytes, not hex string)
	nonceBytes, err := hex.DecodeString(challengeResp.Nonce)
	if err != nil {
		return "", fmt.Errorf("decoding nonce: %w", err)
	}
	signature := ed25519.Sign(privKey, nonceBytes)
	signatureHex := hex.EncodeToString(signature)

	// 4. Verify
	verifyResp, err := apiRequest("POST", "/auth/machine-verify", map[string]string{
		"machine_id": challengeResp.MachineID,
		"nonce":      challengeResp.Nonce,
		"signature":  signatureHex,
	}, "")
	if err != nil {
		return "", fmt.Errorf("machine verify request: %w", err)
	}
	defer verifyResp.Body.Close()
	if err := checkAPIError(verifyResp); err != nil {
		return "", fmt.Errorf("machine verify failed: %w", err)
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(verifyResp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding verify response: %w", err)
	}

	return tokenResp.Token, nil
}
