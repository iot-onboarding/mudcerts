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
mudzipserver listens on http://localhost:8085/ for stuff to sign
using the routines in the mudcerts library.

Usage: mudzipserver

There is a single RESTful call supported:

	POST /mudzip

Input: JSON version of ProductInfo
Returns: 200 and a zip file containing all the certs and a signed MUD file

	or an error.
*/
package main

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	. "github.com/iot-onboarding/mudcerts"
)

var READMEsrc string = `

CAUTION: the keys, certtificates, and signatures provided here are for
demonstration purposes only.  Below are suggestions for production use.

In this directory, you will find the following files:

ca.pem            --> the CA cert used to create other certs in this directory.
cakey.pem         --> the private key associated with ca.pem.
mudsigner.pem     --> the certificate used to sign the mud file.
mudsigner-key.pem --> the private key associated with mudsigner-key.pem
mudcert.pem       --> an IEEE 802.1AR device certificate with MUD extensions
                      signed with ca.pem and cakey.pem
mudkey.pem        --> the private key associated with mudcert.pem
YOURDEVICE.json   --> A MUD file, perhaps generated with mudmaker.org
YOURDEVICE.p7s    --> A detached CMS signature of your MUD file
                      signed with mudsigner.pem.

You can verifiy the signature of the MUD file with the following openssl
command:

 % openssl cms -verify -in YOURDEVICE.p7s -inform DER -content YOURDEVICE.json \
    -CAfile ca.pem -purpose any -out /dev/null

The source code used to build the zip file can be found at the following location:
https://github.com/iot-onboarding/mudcerts

In production use, it is important to protect all private keys.  In particular:

 -  Any certificate authority must be treated with great care
 -  appropriate production controls and device security should be provided
    to protect device keys and any signing keys used.

For more information about Manufacturer Usage Descriptions see RFC 8520 at
https://www.rfc-editor.org/info/rfc8520.  For more information about device
certificates, review IEEE 802.1AR standard at
https://standards.ieee.org/ieee/802.1AR/6995.
`

// postMUD processes a POST on /mudzip with a base64-encoded MUD file
// and returns a zip file.
func postMUD(c *gin.Context) {
	processResponse(c, true)
}

// postMUDNoB64MUD processes a POST on mudNob64ZIP with a JSON string
// and returns a zip file.
func postNoB64MUD(c *gin.Context) {
	processResponse(c, false)
}

// processResponse takes the actual input and based on doB64 either
// takes base64 input or a JSON string to produce a zip file.
func processResponse(c *gin.Context, dob64 bool) {
	var pinfo ProductInfo
	var mudjson string

	if err := c.BindJSON(&pinfo); err != nil {
		return
	}

	cabytes, caPrivKey, err := GenCA(pinfo)
	if err != nil {
		log.Fatal(err)
	}

	cacert, err := x509.ParseCertificate(cabytes)
	if err != nil {
		log.Fatal(err)
	}

	capem := MakePEM(cabytes, "CERTIFICATE")
	mudcert, mudcertPrivKey, err := MakeMUDcert(pinfo, cacert, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	mudsigner, mudsignerPrivKey, err := MakeSignerCert(pinfo, cacert, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	mudcertpem := MakePEM(mudcert, "CERTIFICATE")
	mudsignerpem := MakePEM(mudsigner, "CERTIFICATE")
	caPrivBytes, _ := x509.MarshalECPrivateKey(caPrivKey)
	caPrivkeyPEM := MakePEM(caPrivBytes, "PRIVATE KEY")
	mudPrivBytes, _ := x509.MarshalECPrivateKey(mudcertPrivKey)
	mudPrivKeyPEM := MakePEM(mudPrivBytes, "PRIVATE KEY")
	mudsignerPrivBytes, _ := x509.MarshalECPrivateKey(mudsignerPrivKey)
	mudsignerPrivKeyPEM := MakePEM(mudsignerPrivBytes, "PRIVATE KEY")

	if dob64 == true {
		mudbytes, err := base64.StdEncoding.DecodeString(pinfo.Mudfile)
		if err != nil {
			log.Fatal(err)
		}
		mudjson = string(mudbytes)
	} else {
		mudjson = pinfo.Mudfile
	}

	mudsigncert, err := x509.ParseCertificate(mudsigner)
	mudsig, err := SignMudFile(mudjson, mudsigncert, mudsignerPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	re := regexp.MustCompile(`YOURDEVICE`)
	READMEtxt := re.ReplaceAll([]byte(READMEsrc), []byte(pinfo.Model))

	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	var files = []struct {
		Name, Body string
	}{
		{"README.txt", string(READMEtxt)},
		{"ca.pem", capem.String()},
		{"cakey.pem", caPrivkeyPEM.String()},
		{"mudsigner.pem", mudsignerpem.String()},
		{"mudsigner-key.pem", mudsignerPrivKeyPEM.String()},
		{"mudcert.pem", mudcertpem.String()},
		{"mudkey.pem", mudPrivKeyPEM.String()},
		{pinfo.Model + ".json", string(mudjson)},
	}

	for _, file := range files {
		f, err := w.Create(file.Name)
		if err != nil {
			log.Fatal(err)
		}
		_, err = f.Write([]byte(file.Body))
		if err != nil {
			log.Fatal(err)
		}
	}
	f, err := w.Create(pinfo.Model + ".p7s")
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write(mudsig)

	if err != nil {
		log.Fatal(err)
	}
	err = w.Close()

	if err != nil {
		log.Fatal(err)
	}

	c.Header("Content-Disposition", "attachment; filename=\""+pinfo.Model+".zip"+"\"")

	c.Data(http.StatusOK, "application/zip", buf.Bytes())
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil)
	router.POST("/mudzip", postMUD)
	router.POST("/mudnob64zip", postNoB64MUD)
	router.Run(":8085")
}
