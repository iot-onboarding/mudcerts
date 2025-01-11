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

// Package mudcerts provides a set of functions to generate certificates,
// keys, and signatures relating to MUD files and MUD-enabled devices.
package mudcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"
)

// GenCA takes as input some Manufacturer information, and produce a CA
// cert and associated key.  This can be used to generate a signer
// cert and key.
func GenCA(p ProductInfo) ([]byte, *ecdsa.PrivateKey, error) {

	if p.Manufacturer == "" || len(p.CountryCode) != 2 {
		return nil, nil, errors.New("ProductInfo bad manufacturer or country value")
	}

	serNum, err := certSerial()
	if err != nil {
		return nil, nil, err
	}

	ca := &x509.Certificate{
		SerialNumber: serNum,
		Subject: pkix.Name{
			Organization:       []string{p.Manufacturer},
			OrganizationalUnit: []string{"Example Certificate Authority"},
			Country:            []string{p.CountryCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}

	return caBytes, caPrivKey, nil
}
