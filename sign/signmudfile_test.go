// Copyright 2024 Cisco Systems, Inc. and Affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cms "github.com/github/smimesign/ietf-cms"
	. "github.com/iot-onboarding/mudcerts"
)

// signFixture generates a CA + signer cert and writes signer.pem +
// signer.key to dir. It returns the cert path, key path, and the parsed
// CA cert (for verifying signatures produced by signAll).
func signFixture(t *testing.T, dir string) (certPath, keyPath string, caCert *x509.Certificate) {
	t.Helper()
	p := ProductInfo{
		Manufacturer: "ACME",
		CountryCode:  "US",
		Model:        "Device1",
		MudUrl:       "https://example.com/mud/Device1",
		EmailAddress: "signer@example.com",
	}
	caBytes, caKey, err := GenCA(p)
	if err != nil {
		t.Fatalf("GenCA: %v", err)
	}
	caCert, err = x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	signerBytes, signerKey, err := MakeSignerCert(p, caCert, caKey)
	if err != nil {
		t.Fatalf("MakeSignerCert: %v", err)
	}
	signerPEM := MakePEM(signerBytes, "CERTIFICATE")
	keyDER, err := x509.MarshalECPrivateKey(signerKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := MakePEM(keyDER, "EC PRIVATE KEY")

	certPath = filepath.Join(dir, "signer.pem")
	keyPath = filepath.Join(dir, "signer.key")
	if err := os.WriteFile(certPath, signerPEM.Bytes(), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM.Bytes(), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath, caCert
}

func TestSignAllHappyPath(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caCert := signFixture(t, dir)

	mudPath := filepath.Join(dir, "device.json")
	mud := []byte(`{"ietf-mud:mud":{"mud-version":1}}`)
	if err := os.WriteFile(mudPath, mud, 0o600); err != nil {
		t.Fatalf("write mud: %v", err)
	}

	if err := signAll(certPath, keyPath, []string{mudPath}); err != nil {
		t.Fatalf("signAll: %v", err)
	}

	sigPath := filepath.Join(dir, "device.p7s")
	sigBytes, err := os.ReadFile(sigPath) //nolint:gosec // test: sigPath is under t.TempDir()
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}

	// Round-trip: the produced signature must verify against the CA.
	sd, err := cms.ParseSignedData(sigBytes)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := sd.VerifyDetached(mud, x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
}

// TestSignAllRejectsCorruptKey is the regression test for #22: with the
// old code, a key file whose contents fail to parse as an EC private
// key produced a nil key and a later panic. signAll must now return a
// non-nil error.
func TestSignAllRejectsCorruptKey(t *testing.T) {
	dir := t.TempDir()
	certPath, _, _ := signFixture(t, dir)

	corrupt := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("not a valid SEC1 key"),
	})
	corruptKey := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(corruptKey, corrupt, 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}

	mudPath := filepath.Join(dir, "device.json")
	if err := os.WriteFile(mudPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write mud: %v", err)
	}

	err := signAll(certPath, corruptKey, []string{mudPath})
	if err == nil {
		t.Fatal("signAll(corrupt key) returned nil; want parse error")
	}
	if !strings.Contains(err.Error(), "parse EC private key") {
		t.Fatalf("error = %v; want substring %q", err, "parse EC private key")
	}
}

// TestSignAllRejectsWrongPEMType ensures a swapped cert-as-key (or any
// non-EC-PRIVATE-KEY PEM type) is detected before parsing.
func TestSignAllRejectsWrongPEMType(t *testing.T) {
	dir := t.TempDir()
	certPath, _, _ := signFixture(t, dir)

	// Use the CERTIFICATE PEM in place of the key file.
	mudPath := filepath.Join(dir, "device.json")
	if err := os.WriteFile(mudPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write mud: %v", err)
	}

	err := signAll(certPath, certPath, []string{mudPath})
	if err == nil {
		t.Fatal("signAll(cert as key) returned nil; want type error")
	}
	if !strings.Contains(err.Error(), "expected EC PRIVATE KEY") {
		t.Fatalf("error = %v; want substring %q", err, "expected EC PRIVATE KEY")
	}
}

func TestSignAllNoFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := signFixture(t, dir)
	if err := signAll(certPath, keyPath, nil); err == nil {
		t.Fatal("signAll(no files) returned nil; want error")
	}
}
