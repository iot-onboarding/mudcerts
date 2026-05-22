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

/*
signmudfile takes as input a key, a signer, and one or more files,
and generates a CMS signature, by appending .p7s to the file. The
trailing extension is dropped.

Usage:

	signmudfile [flags] [path ...]

	-cert string
	      Name of file containing signing cert (default "signer.pem")
	-key string
	      Signer key (default "signer.key")
*/
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"

	mudcerts "github.com/iot-onboarding/mudcerts"
)

// outExt strips the final extension and replaces it with .p7s.
var outExt = regexp.MustCompile(`\.[^./\\]*$`)

// loadCert reads a PEM file and returns the first CERTIFICATE block,
// parsed. It errors if the file is missing, contains no PEM block, the
// first block is not a CERTIFICATE, or the certificate fails to parse.
func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI tool: path comes from -cert flag
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block in %s, got %q", path, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

// loadECKey reads a PEM file and returns the first EC PRIVATE KEY block,
// parsed. Unlike the previous implementation, the parse error is
// captured directly and surfaced; a corrupt key file no longer yields a
// nil key that later panics inside SignMudFile (CWE-252 / CWE-476).
func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI tool: path comes from -key flag
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "EC PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected EC PRIVATE KEY PEM block in %s, got %q", path, block.Type)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key %s: %w", path, err)
	}
	return key, nil
}

// signFile signs a single mudfile and writes the detached CMS
// signature to a sibling file with the input extension replaced by .p7s.
func signFile(in string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	mudfile, err := os.ReadFile(in) //nolint:gosec // CLI tool: in is a positional argument
	if err != nil {
		return fmt.Errorf("read mud file %s: %w", in, err)
	}
	out := outExt.ReplaceAllLiteralString(in, "") + ".p7s"
	der, err := mudcerts.SignMudFile(string(mudfile), cert, key)
	if err != nil {
		return fmt.Errorf("sign %s: %w", in, err)
	}
	// G703: out is derived from the operator-supplied input path on the
	// command line; writing the signature next to it is the documented
	// behavior of this CLI.
	if err := os.WriteFile(out, der, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("write %s: %w", out, err)
	}
	return nil
}

// signAll loads the signer credentials and signs every file in paths.
// It is split out from main so tests can exercise the full flow without
// spawning a process.
func signAll(certPath, keyPath string, paths []string) error {
	if len(paths) == 0 {
		return errors.New("no files to sign")
	}
	cert, err := loadCert(certPath)
	if err != nil {
		return err
	}
	key, err := loadECKey(keyPath)
	if err != nil {
		return err
	}
	for _, fn := range paths {
		if err := signFile(fn, cert, key); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	certfile := flag.String("cert", "signer.pem",
		"Name of file containing signing cert")
	keyfile := flag.String("key", "signer.key", "Signer key")
	flag.Parse()
	if err := signAll(*certfile, *keyfile, flag.Args()); err != nil {
		log.Fatal(err)
	}
}
