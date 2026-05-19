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
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	. "github.com/iot-onboarding/mudcerts"
)

// maxRequestBytes caps the size of any incoming request body. A MUD file
// plus the surrounding ProductInfo JSON should comfortably fit; anything
// larger is treated as abuse.
const maxRequestBytes = 150 * 1024 // 150 KiB

// limitBody installs an http.MaxBytesReader on every incoming request so
// that BindJSON (and any other body reader) cannot exhaust memory.
func limitBody(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}

// isBodyTooLarge reports whether err originated from http.MaxBytesReader.
// JSON binders may wrap or stringify the underlying error, so we accept
// either the typed error or the canonical message.
func isBodyTooLarge(err error) bool {
	if err == nil {
		return false
	}
	var mbErr *http.MaxBytesError
	if errors.As(err, &mbErr) {
		return true
	}
	return strings.Contains(err.Error(), "request body too large")
}

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

// httpError logs the error server-side and returns a JSON error body to the
// client with the given HTTP status, aborting any further handler processing.
func httpError(c *gin.Context, status int, msg string, err error) {
	log.Printf("mudzip %s: %v", msg, err)
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}

// postMUD processes a POST on /mudzip and returns a zip file.
func postMUD(c *gin.Context) {
	var pinfo ProductInfo

	if err := c.ShouldBindJSON(&pinfo); err != nil {
		if isBodyTooLarge(err) {
			httpError(c, http.StatusRequestEntityTooLarge, "request body too large", err)
			return
		}
		httpError(c, http.StatusBadRequest, "invalid JSON body", err)
		return
	}

	if pinfo.Model == "" {
		httpError(c, http.StatusBadRequest, "missing required field: Model", nil)
		return
	}
	if pinfo.Mudfile == "" {
		httpError(c, http.StatusBadRequest, "missing required field: Mudfile", nil)
		return
	}

	mudjson, err := base64.StdEncoding.DecodeString(pinfo.Mudfile)
	if err != nil {
		httpError(c, http.StatusBadRequest, "Mudfile is not valid base64", err)
		return
	}

	cabytes, caPrivKey, err := GenCA(pinfo)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to generate CA", err)
		return
	}

	cacert, err := x509.ParseCertificate(cabytes)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to parse CA certificate", err)
		return
	}

	capem := MakePEM(cabytes, "CERTIFICATE")
	mudcert, mudcertPrivKey, err := MakeMUDcert(pinfo, cacert, caPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to create MUD certificate", err)
		return
	}

	mudsigner, mudsignerPrivKey, err := MakeSignerCert(pinfo, cacert, caPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to create MUD signer certificate", err)
		return
	}

	mudcertpem := MakePEM(mudcert, "CERTIFICATE")
	mudsignerpem := MakePEM(mudsigner, "CERTIFICATE")
	caPrivBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to marshal CA private key", err)
		return
	}
	caPrivkeyPEM := MakePEM(caPrivBytes, "PRIVATE KEY")
	mudPrivBytes, err := x509.MarshalECPrivateKey(mudcertPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to marshal MUD private key", err)
		return
	}
	mudPrivKeyPEM := MakePEM(mudPrivBytes, "PRIVATE KEY")
	mudsignerPrivBytes, err := x509.MarshalECPrivateKey(mudsignerPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to marshal MUD signer private key", err)
		return
	}
	mudsignerPrivKeyPEM := MakePEM(mudsignerPrivBytes, "PRIVATE KEY")

	mudsigncert, err := x509.ParseCertificate(mudsigner)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to parse MUD signer certificate", err)
		return
	}
	mudsig, err := SignMudFile(string(mudjson), mudsigncert, mudsignerPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to sign MUD file", err)
		return
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
			httpError(c, http.StatusInternalServerError, "failed to create zip entry", err)
			return
		}
		_, err = f.Write([]byte(file.Body))
		if err != nil {
			httpError(c, http.StatusInternalServerError, "failed to write zip entry", err)
			return
		}
	}
	f, err := w.Create(pinfo.Model + ".p7s")
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to create signature zip entry", err)
		return
	}

	if _, err = f.Write(mudsig); err != nil {
		httpError(c, http.StatusInternalServerError, "failed to write signature zip entry", err)
		return
	}
	if err = w.Close(); err != nil {
		httpError(c, http.StatusInternalServerError, "failed to finalize zip archive", err)
		return
	}

	c.Header("Content-Disposition", "attachment; filename=\""+pinfo.Model+".zip"+"\"")

	c.Data(http.StatusOK, "application/zip", buf.Bytes())
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil)
	router.Use(limitBody(maxRequestBytes))
	router.POST("/mudzip", postMUD)
	router.Run(":8085")
}
