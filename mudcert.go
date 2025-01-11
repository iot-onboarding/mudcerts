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
	"encoding/asn1"
	"fmt"
	"time"
)

// MakeMUDcert returns an IEEE 802.1AR certificate with MUD extensions, and
// associated key. You can use MakeSignerCert in front of this routine.
func MakeMUDcert(p ProductInfo, ca *x509.Certificate,
	caPrivKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {

	// create a mud-url extension.

	urlentry, err := asn1.Marshal(p.MudUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}
	mudurlExtension := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 25},
		Value: urlentry,
	}

	signerName := pkix.Name{
		Organization:       []string{p.Manufacturer},
		OrganizationalUnit: []string{"Example Certificate Authority"},
		Country:            []string{p.CountryCode},
	}

	mudSignerSeq, err := asn1.Marshal(signerName.ToRDNSequence())

	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}

	mudSignerExt := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30},
		Value: mudSignerSeq,
	}
	ski, err := certSKI()
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}
	serNum, err := certSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err)
	}

	cert := &x509.Certificate{
		SerialNumber: serNum,
		Subject: pkix.Name{
			Organization: []string{p.Manufacturer},
			Country:      []string{p.CountryCode},
			CommonName:   p.Model,
			SerialNumber: p.SerialNumber,
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().AddDate(10, 0, 0),
		SubjectKeyId:    ski,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{mudurlExtension, mudSignerExt},
		KeyUsage:        x509.KeyUsageDigitalSignature,
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
