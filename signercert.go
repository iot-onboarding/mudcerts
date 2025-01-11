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
	"fmt"
	"time"
)

// MakeSignerCert returns an end entity certificate used solely for
// signing MUD files.
func MakeSignerCert(p ProductInfo,
	ca *x509.Certificate, caPrivKey *ecdsa.PrivateKey) ([]byte,
	*ecdsa.PrivateKey, error) {

	serNum, err := certSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}

	ski, err := certSKI()
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}

	cert := &x509.Certificate{
		SerialNumber: serNum,
		Subject: pkix.Name{
			Organization:       []string{p.Manufacturer},
			OrganizationalUnit: []string{"Example MUDFile Signer"},
			Country:            []string{p.CountryCode},
			CommonName:         p.EmailAddress,
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		SubjectKeyId:   ski,
		EmailAddresses: []string{p.EmailAddress},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}
	return certBytes, certPrivKey, nil
}
