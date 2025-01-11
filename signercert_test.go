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

package mudcerts

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestSignerCert tests SignerCert function by providing a ProductInfo
// struct, a CA Cert and a key.
func TestSignerCert(t *testing.T) {
	caPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIB7jCCAZWgAwIBAgIGBhmUP2WhMAoGCCqGSM49BAMCME0xCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1BQ01FIFN1cHBsaWVzMSYwJAYDVQQLEx1FeGFtcGxlIENlcnRp
ZmljYXRlIEF1dGhvcml0eTAeFw0yNDEyMTkwODA2MDVaFw0zNDEyMTkwODA2MDVa
ME0xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1BQ01FIFN1cHBsaWVzMSYwJAYDVQQL
Ex1FeGFtcGxlIENlcnRpZmljYXRlIEF1dGhvcml0eTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABGUJiJL2pYtDdIGTkWqlMCNhBHp4+8efkOaa1JaEtXTRWsFd1iWe
M9NI+FjVdFL1FpffFxelduEaOPEnppVGhFyjYTBfMA4GA1UdDwEB/wQEAwIChDAd
BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUrdw+NDYKT0o/OXYXArttebNUgJswCgYIKoZIzj0EAwIDRwAwRAIg
PDAKUEatMHeVy6ViNyNzjZGnFRIKvaTBh0V2ONiXPfgCIEZE61/2Hm1jNb15Xoj6
m3XSQ0IdH3wsJUsWTd81hIAn
-----END CERTIFICATE-----`)

	cakeyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MHcCAQEEIOtAg1v3Dh4pvzt8qAftTepKStrA3sbjR52bEAcLve+2oAoGCCqGSM49
AwEHoUQDQgAEZQmIkvali0N0gZORaqUwI2EEenj7x5+Q5prUloS1dNFawV3WJZ4z
00j4WNV0UvUWl98XF6V24Ro48SemlUaEXA==
-----END PRIVATE KEY-----`)

	pinfo := ProductInfo{
		Manufacturer: "Test Signer",
		CountryCode:  "US",
		Model:        "Test Model",
		MudUrl:       "https://example.com/test.json",
		EmailAddress: "signer@test.example.com",
	}
	block, _ := pem.Decode(caPEM)
	cacert, _ := x509.ParseCertificate(block.Bytes)
	block, _ = pem.Decode(cakeyPEM)
	caPrivKey, _ := x509.ParseECPrivateKey(block.Bytes)
	mudbytes, _, err := MakeSignerCert(pinfo, cacert,
		caPrivKey)
	mudsigner, _ := x509.ParseCertificate(mudbytes)
	if err != nil {
		t.Fatalf(`MakeSignerCert() did not generate a valid certiticate %v`, err)
	}
	if mudsigner.Issuer.Organization[0] != "ACME Supplies" {
		t.Fatalf(`MakeSignerCert() Issuer wanted "ACME Supplies", got %s`,
			mudsigner.Issuer.Organization)
	}
	if mudsigner.EmailAddresses[0] != pinfo.EmailAddress {
		t.Fatalf(`MakeSignerCert Email wanted %s, got %s`,
			pinfo.EmailAddress, mudsigner.EmailAddresses[0])
	}
}
