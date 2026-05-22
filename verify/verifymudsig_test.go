// Copyright 2024 Cisco Systems, Inc. and Affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mudcerts "github.com/iot-onboarding/mudcerts"
)

// fixtures holds an in-memory set of generated artifacts plus the
// directory containing PEM/DER files on disk.
type fixtures struct {
	dir       string
	caPath    string
	signerPEM string // signer cert PEM written to disk (for use as -ca in negative tests)
	sigPath   string
	mudPath   string

	// retained for advanced tests that want to mutate things.
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	signerCert  *x509.Certificate
	signerKey   *ecdsa.PrivateKey
	mudContents []byte
}

// newFixtures generates a CA + signer + signed MUD file and writes
// everything to a temp directory.
func newFixtures(t *testing.T) *fixtures {
	t.Helper()
	dir := t.TempDir()
	pinfo := mudcerts.ProductInfo{
		Manufacturer: "Test Co",
		CountryCode:  "US",
		Model:        "TestModel",
		MudUrl:       "https://example.com/test.json",
		EmailAddress: "signer@example.com",
		SerialNumber: "SN-1",
	}

	caBytes, caKey, err := mudcerts.GenCA(pinfo)
	if err != nil {
		t.Fatalf("GenCA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("ParseCertificate(ca): %v", err)
	}

	signerBytes, signerKey, err := mudcerts.MakeSignerCert(pinfo, caCert, caKey)
	if err != nil {
		t.Fatalf("MakeSignerCert: %v", err)
	}
	signerCert, err := x509.ParseCertificate(signerBytes)
	if err != nil {
		t.Fatalf("ParseCertificate(signer): %v", err)
	}

	mud := []byte(`{"ietf-mud:mud":{"mud-version":1,"mud-url":"https://example.com/test.json"}}`)
	sig, err := mudcerts.SignMudFile(string(mud), signerCert, signerKey)
	if err != nil {
		t.Fatalf("SignMudFile: %v", err)
	}

	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	caPath := writeFile("ca.pem", mudcerts.MakePEM(caBytes, "CERTIFICATE").Bytes())
	signerPath := writeFile("signer.pem", mudcerts.MakePEM(signerBytes, "CERTIFICATE").Bytes())
	sigPath := writeFile("mudfile.p7s", sig)
	mudPath := writeFile("mud.json", mud)

	return &fixtures{
		dir:         dir,
		caPath:      caPath,
		signerPEM:   signerPath,
		sigPath:     sigPath,
		mudPath:     mudPath,
		caCert:      caCert,
		caKey:       caKey,
		signerCert:  signerCert,
		signerKey:   signerKey,
		mudContents: mud,
	}
}

// TestVerifyHappyPath confirms a freshly-generated CA + signer + signed
// MUD file verifies successfully through the new code path.
func TestVerifyHappyPath(t *testing.T) {
	f := newFixtures(t)
	if err := verify(f.caPath, "", f.sigPath, f.mudPath, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestVerifyRejectsLeafAsRoot is the regression test for issue #21:
// passing the signer leaf as the trust anchor must NOT verify
// successfully, regardless of whether the signature is otherwise valid.
func TestVerifyRejectsLeafAsRoot(t *testing.T) {
	f := newFixtures(t)
	err := verify(f.signerPEM, "", f.sigPath, f.mudPath, time.Now())
	if err == nil {
		t.Fatal("verify accepted signer leaf as trust anchor; want error")
	}
	// Must be rejected at the IsCA gate, not just by the verifier.
	if want := "is not a CA"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v; want substring %q", err, want)
	}
}

// TestVerifyRejectsWrongRoot confirms that a signature produced by a
// different CA chain does not verify against an unrelated trust anchor.
func TestVerifyRejectsWrongRoot(t *testing.T) {
	good := newFixtures(t)
	other := newFixtures(t) // independent CA

	err := verify(other.caPath, "", good.sigPath, good.mudPath, time.Now())
	if err == nil {
		t.Fatal("verify accepted signature under unrelated CA; want error")
	}
}

// TestVerifyRejectsTamperedMUD confirms that altering the signed payload
// causes verification to fail.
func TestVerifyRejectsTamperedMUD(t *testing.T) {
	f := newFixtures(t)
	tampered := append([]byte{}, f.mudContents...)
	tampered[0] ^= 0xFF
	tamperedPath := filepath.Join(f.dir, "mud-tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if err := verify(f.caPath, "", f.sigPath, tamperedPath, time.Now()); err == nil {
		t.Fatal("verify accepted tampered MUD file; want error")
	}
}

// TestLoadPEMCertsErrors exercises the file-loading rules in isolation.
func TestLoadPEMCertsErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty path", func(t *testing.T) {
		if _, err := loadPEMCerts(""); err == nil {
			t.Fatal("loadPEMCerts(\"\") returned nil error")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := loadPEMCerts(filepath.Join(dir, "nope.pem")); err == nil {
			t.Fatal("loadPEMCerts(missing) returned nil error")
		}
	})

	t.Run("no certificate blocks", func(t *testing.T) {
		p := filepath.Join(dir, "empty.pem")
		if err := os.WriteFile(p, []byte("not a PEM file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPEMCerts(p); err == nil {
			t.Fatal("loadPEMCerts(no-certs) returned nil error")
		}
	})
}
