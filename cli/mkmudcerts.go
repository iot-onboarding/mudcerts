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
mkmudcerts takes as input product information and generates a set of
certificates and keys.

Usage:

  mkmudcerts [-flags]

The flags are:

-cc string
        Country Code of Manufacturer (default "US")
  -mfg string
        Name of Manufacturer (default "ACME Supplies")
  -mod string
        Device Model (default "Hornblower 2000")
  -mudurl string
        URL for MUDfile (default "https://...")
  -ser string
        A device Serial Number (default "SN12345")


*/

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	. "github.com/iot-onboarding/mudcerts"
)

func main() {

	mfg := flag.String("mfg", "ACME Supplies", "Name of Manufacturer")
	mfgCC := flag.String("cc", "US", "Country Code of Manufacturer")
	model := flag.String("mod", "Hornblower 2000", "Device Model")
	mudurl := flag.String("mudurl", "https://...", "URL for MUDfile")
	sernum := flag.String("ser", "SN12345", "A device Serial Number")
	emailaddr := flag.String("email","user@mudsigner.example.com",
		"An email address as a SubjectAltName")

	flag.Parse()

	pinfo := ProductInfo{
		Manufacturer: *mfg,
		CountryCode:  *mfgCC,
		Model:        *model,
		MudUrl:       *mudurl,
		SerialNumber: *sernum,
		EmailAddress: *emailaddr,
	}

	cabytes, caPrivKey, err := GenCA(pinfo)
	if err != nil {
		log.Fatal(err)
	}

	cacert, err := x509.ParseCertificate(cabytes)
	if err != nil {
		log.Fatal(err)
	}

	capem, err := MakePEM(cabytes, "CERTIFICATE")
	if err != nil {
		log.Fatal(err)
	}
	mudcert, mudcertPrivKey, err := MakeMUDcert(pinfo, cacert, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	mudsigner, mudsignerPrivKey, err := MakeSignerCert(pinfo, cacert, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	mudcertpem, err := MakePEM(mudcert, "CERTIFICATE")
	if err != nil {
		log.Fatal(err)
	}
	caPrivBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	caPrivkeyPEM, err := MakePEM(caPrivBytes, "PRIVATE KEY")
	if err != nil {
		log.Fatal(err)
	}
	mudPrivBytes, err := x509.MarshalECPrivateKey(mudcertPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	mudPrivKeyPEM, err := MakePEM(mudPrivBytes, "PRIVATE KEY")
	if err != nil {
		log.Fatal(err)
	}
	mudsignerPEM, err := MakePEM(mudsigner, "CERTIFICATE")
	if err != nil {
		log.Fatal(err)
	}
	mudsignerPrivBytes, err := x509.MarshalECPrivateKey(mudsignerPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	mudsignerPrivKeyPEM, err := MakePEM(mudsignerPrivBytes, "PRIVATE KEY")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(capem)
	fmt.Println(caPrivkeyPEM)
	fmt.Println(mudsignerPEM)
	fmt.Println(mudsignerPrivKeyPEM)
	fmt.Println(mudcertpem)
	fmt.Println(mudPrivKeyPEM)
}
