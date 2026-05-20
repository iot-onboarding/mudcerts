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

/*
verifymudsig verifies a MUD signature on a file against a configured
set of trust anchors.

Usage:

  verifymudsig [flags] {mud file to be verified}

The flags are as follows:

  -ca string
        Path to a PEM file containing one or more trust anchor
        (CA) certificates. Each certificate in this file MUST
        carry IsCA=true; any other certificate is rejected.
        Required. (default "ca.pem")
  -int string
        Optional path to a PEM file containing intermediate
        certificates that may appear in the signer's chain.
        Not used as trust anchors.
  -sig string
        Name of file containing DER signature. (default
        "mudfile.p7s")
*/
import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
)

// loadPEMCerts reads path and returns every CERTIFICATE block parsed.
// Non-CERTIFICATE blocks are silently skipped (e.g. PRIVATE KEY).
// Returns an error if path is empty, unreadable, contains no
// CERTIFICATE blocks, or any block fails to parse.
func loadPEMCerts(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate in %s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in %s", path)
	}
	return certs, nil
}

// buildPools loads CA and (optional) intermediate certificates and
// builds the corresponding pools. Every certificate supplied via caPath
// MUST have IsCA=true; supplying a non-CA certificate as a trust anchor
// is the bug fixed by issue #21 and is rejected here.
func buildPools(caPath, intPath string) (roots, intermediates *x509.CertPool, err error) {
	cas, err := loadPEMCerts(caPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: %w", err)
	}
	roots = x509.NewCertPool()
	for _, c := range cas {
		if !c.IsCA {
			return nil, nil, fmt.Errorf("ca: certificate %q is not a CA (IsCA=false)", c.Subject)
		}
		roots.AddCert(c)
	}

	intermediates = x509.NewCertPool()
	if intPath != "" {
		ints, err := loadPEMCerts(intPath)
		if err != nil {
			return nil, nil, fmt.Errorf("intermediates: %w", err)
		}
		for _, c := range ints {
			intermediates.AddCert(c)
		}
	}
	return roots, intermediates, nil
}

// verify performs the full signature check. It is split out from main
// so that tests can exercise it without spawning a process.
//
// NOTE: KeyUsages is intentionally left as ExtKeyUsageAny because the
// MUD signer certificates produced by this repository's MakeSignerCert
// do not currently carry an Extended Key Usage extension. Once
// MakeSignerCert is updated to set ExtKeyUsageEmailProtection, this
// should be tightened accordingly.
func verify(caPath, intPath, sigPath, mudPath string, now time.Time) error {
	roots, intermediates, err := buildPools(caPath, intPath)
	if err != nil {
		return err
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read sig %s: %w", sigPath, err)
	}
	mudfile, err := os.ReadFile(mudPath)
	if err != nil {
		return fmt.Errorf("read mud file %s: %w", mudPath, err)
	}

	sd, err := cms.ParseSignedData(sig)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	if _, err := sd.VerifyDetached(mudfile, opts); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func main() {
	caFlag := flag.String("ca", "ca.pem",
		"Path to PEM file with one or more trust anchor (CA) certificates")
	intFlag := flag.String("int", "",
		"Optional path to PEM file with intermediate certificates")
	sigFlag := flag.String("sig", "mudfile.p7s",
		"Path to DER signature file")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("verifymudsig: provide exactly one MUD file path to verify")
	}

	if err := verify(*caFlag, *intFlag, *sigFlag, flag.Args()[0], time.Now()); err != nil {
		log.Fatalf("verifymudsig: %v", err)
	}
	fmt.Println("Ok.")
}
