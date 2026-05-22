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
	"net/mail"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	mudcerts "github.com/iot-onboarding/mudcerts"
)

// maxRequestBytes caps the size of any incoming request body. A MUD file
// plus the surrounding ProductInfo JSON should comfortably fit; anything
// larger is treated as abuse.
const maxRequestBytes = 150 * 1024 // 150 KiB

// acquireTimeout bounds how long a request will wait for a concurrency
// slot before the server gives up and returns 429. Kept short so that
// clients fail fast under sustained load rather than queueing forever
// and exhausting server-side resources (sockets, goroutines, memory).
const acquireTimeout = 100 * time.Millisecond

// concurrencyLimiter returns a gin middleware that admits at most
// `capacity` concurrent requests through the protected handler chain.
// Excess requests wait up to `timeout` for a slot to free; if none is
// available they are rejected with HTTP 429 and a Retry-After header.
//
// Each /mudzip request performs three ECDSA key generations plus a CMS
// sign, all CPU-bound. Without a cap, a handful of concurrent callers
// can saturate the host (CWE-770). The semaphore here caps in-flight
// crypto work to a value proportional to available CPUs. Operators are
// still expected to run this service behind a reverse proxy that
// enforces per-IP rate limits.
func concurrencyLimiter(capacity int, timeout time.Duration) gin.HandlerFunc {
	if capacity < 1 {
		capacity = 1
	}
	sem := make(chan struct{}, capacity)
	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
		case <-time.After(timeout):
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "server busy, try again later",
			})
		case <-c.Request.Context().Done():
			c.AbortWithStatus(499) // client closed request
		}
	}
}

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

// modelUnsafe matches any rune that is NOT safe to embed in a zip entry
// name or a Content-Disposition filename. The Model field itself is
// free-form identity text (it is also placed in X.509 CN), but anywhere
// it ends up in a filename it must first be passed through safeModel,
// which replaces each unsafe rune with '_' (CWE-22 / CWE-93).
var modelUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// safeModel returns a filename-safe rendering of the Model field.
// Callers must have already validated that p.Model is non-empty,
// <= 64 runes, and contains only printable, non-control characters
// (see validateProductInfo).
func safeModel(m string) string {
	s := modelUnsafe.ReplaceAllString(m, "_")
	if s == "" {
		return "device"
	}
	return s
}

// printableField requires 1..max printable, non-control characters and
// forbids CR/LF entirely. Used for free-form text fields that end up
// inside X.509 subject components.
func printableField(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validateProductInfo enforces server-side constraints on every field
// before any crypto or zip work is performed. Returning a descriptive
// error lets the caller surface a 400 to the client.
func validateProductInfo(p mudcerts.ProductInfo) error {
	if !printableField(p.Model, 64) {
		return errors.New("model must be 1-64 printable characters")
	}
	if !printableField(p.Manufacturer, 64) {
		return errors.New("manufacturer must be 1-64 printable characters")
	}
	if len(p.CountryCode) != 2 ||
		p.CountryCode[0] < 'A' || p.CountryCode[0] > 'Z' ||
		p.CountryCode[1] < 'A' || p.CountryCode[1] > 'Z' {
		return errors.New("CountryCode must be exactly 2 uppercase ASCII letters")
	}
	if p.SerialNumber != "" && !printableField(p.SerialNumber, 64) {
		return errors.New("SerialNumber must be 1-64 printable characters")
	}
	if p.MudUrl == "" {
		return errors.New("MudUrl is required")
	}
	if len(p.MudUrl) > 255 {
		return errors.New("MudUrl must be <= 255 characters")
	}
	u, err := url.Parse(p.MudUrl)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("mudUrl must be a valid https:// URL")
	}
	if p.EmailAddress != "" {
		if !printableField(p.EmailAddress, 254) {
			return errors.New("EmailAddress contains invalid characters")
		}
		if _, err := mail.ParseAddress(p.EmailAddress); err != nil {
			return errors.New("EmailAddress is not a valid address")
		}
	}
	if p.Mudfile == "" {
		return errors.New("mudfile is required")
	}
	return nil
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
command. The -binary flag is required: the MUD file is signed verbatim
(as binary CMS data), and without -binary openssl performs SMIME-style
CRLF canonicalization on the content and the digest no longer matches.

 % openssl cms -verify -in YOURDEVICE.p7s -inform DER -content YOURDEVICE.json \
    -CAfile ca.pem -purpose any -binary -out /dev/null

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
	var pinfo mudcerts.ProductInfo

	if err := c.ShouldBindJSON(&pinfo); err != nil {
		if isBodyTooLarge(err) {
			httpError(c, http.StatusRequestEntityTooLarge, "request body too large", err)
			return
		}
		httpError(c, http.StatusBadRequest, "invalid JSON body", err)
		return
	}

	if err := validateProductInfo(pinfo); err != nil {
		httpError(c, http.StatusBadRequest, err.Error(), err)
		return
	}

	mudjson, err := base64.StdEncoding.DecodeString(pinfo.Mudfile)
	if err != nil {
		httpError(c, http.StatusBadRequest, "Mudfile is not valid base64", err)
		return
	}

	cabytes, caPrivKey, err := mudcerts.GenCA(pinfo)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to generate CA", err)
		return
	}

	cacert, err := x509.ParseCertificate(cabytes)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to parse CA certificate", err)
		return
	}

	capem := mudcerts.MakePEM(cabytes, "CERTIFICATE")
	mudcert, mudcertPrivKey, err := mudcerts.MakeMUDcert(pinfo, cacert, caPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to create MUD certificate", err)
		return
	}

	mudsigner, mudsignerPrivKey, err := mudcerts.MakeSignerCert(pinfo, cacert, caPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to create MUD signer certificate", err)
		return
	}

	mudcertpem := mudcerts.MakePEM(mudcert, "CERTIFICATE")
	mudsignerpem := mudcerts.MakePEM(mudsigner, "CERTIFICATE")
	caPrivBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to marshal CA private key", err)
		return
	}
	caPrivkeyPEM := mudcerts.MakePEM(caPrivBytes, "PRIVATE KEY")
	mudPrivBytes, err := x509.MarshalECPrivateKey(mudcertPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to marshal MUD private key", err)
		return
	}
	mudPrivKeyPEM := mudcerts.MakePEM(mudPrivBytes, "PRIVATE KEY")
	mudsignerPrivBytes, err := x509.MarshalECPrivateKey(mudsignerPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to marshal MUD signer private key", err)
		return
	}
	mudsignerPrivKeyPEM := mudcerts.MakePEM(mudsignerPrivBytes, "PRIVATE KEY")

	mudsigncert, err := x509.ParseCertificate(mudsigner)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to parse MUD signer certificate", err)
		return
	}
	mudsig, err := mudcerts.SignMudFile(string(mudjson), mudsigncert, mudsignerPrivKey)
	if err != nil {
		httpError(c, http.StatusInternalServerError, "failed to sign MUD file", err)
		return
	}

	// safeName is used for everything that ends up in a filename, header,
	// or README placeholder. pinfo.Model itself is identity text and may
	// contain spaces or other characters that would be unsafe to embed.
	safeName := safeModel(pinfo.Model)

	re := regexp.MustCompile(`YOURDEVICE`)
	READMEtxt := re.ReplaceAll([]byte(READMEsrc), []byte(safeName))

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
		{safeName + ".json", string(mudjson)},
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
	f, err := w.Create(safeName + ".p7s")
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

	c.Header("Content-Disposition", "attachment; filename=\""+safeName+".zip"+"\"")

	c.Data(http.StatusOK, "application/zip", buf.Bytes())
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("mudzip: SetTrustedProxies: %v", err)
	}
	router.Use(limitBody(maxRequestBytes))
	router.Use(concurrencyLimiter(runtime.NumCPU(), acquireTimeout))
	router.POST("/mudzip", postMUD)
	if err := router.Run(":8085"); err != nil {
		log.Fatalf("mudzip: Run: %v", err)
	}
}
