// Copyright 2024 Cisco Systems, Inc. and Affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	. "github.com/iot-onboarding/mudcerts"
)

// newTestRouter builds a gin router wired up the same way main() does,
// including the body-size limit middleware.
func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(limitBody(maxRequestBytes))
	r.POST("/mudzip", postMUD)
	return r
}

// TestPostMUDProducesZip drives postMUD with a valid ProductInfo and
// verifies that a 200 response is returned containing a zip archive
// with all of the expected entries.
func TestPostMUDProducesZip(t *testing.T) {
	mudjson := `{"ietf-mud:mud":{"mud-version":1,"mud-url":"https://example.com/test.json"}}`

	pinfo := ProductInfo{
		Manufacturer: "ACME Supplies",
		Model:        "TestDevice",
		CountryCode:  "US",
		MudUrl:       "https://example.com/test.json",
		SerialNumber: "SN-0001",
		EmailAddress: "signer@example.com",
		Mudfile:      base64.StdEncoding.EncodeToString([]byte(mudjson)),
	}

	body, err := json.Marshal(pinfo)
	if err != nil {
		t.Fatalf("json.Marshal(pinfo) failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mudzip", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	newTestRouter().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q; want 200", w.Code, w.Body.String())
	}

	if got, want := w.Header().Get("Content-Type"), "application/zip"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader failed: %v", err)
	}

	want := []string{
		"README.txt",
		"ca.pem",
		"cakey.pem",
		"mudsigner.pem",
		"mudsigner-key.pem",
		"mudcert.pem",
		"mudkey.pem",
		pinfo.Model + ".json",
		pinfo.Model + ".p7s",
	}

	got := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		got[f.Name] = f
	}
	for _, name := range want {
		f, ok := got[name]
		if !ok {
			t.Errorf("zip missing entry %q", name)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Errorf("open %q: %v", name, err)
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Errorf("read %q: %v", name, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("entry %q is empty", name)
		}
	}

	// The MUD JSON entry should round-trip the input bytes verbatim.
	jsonEntry, ok := got[pinfo.Model+".json"]
	if !ok {
		t.Fatalf("zip missing %s.json", pinfo.Model)
	}
	rc, err := jsonEntry.Open()
	if err != nil {
		t.Fatalf("open mud json: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read mud json: %v", err)
	}
	if string(data) != mudjson {
		t.Errorf("mud json = %q, want %q", string(data), mudjson)
	}
}

// TestREADMEOpensslVerifyHasBinary guards against a regression where the
// openssl verification snippet in README.txt is missing the -binary flag.
// Without -binary, openssl applies SMIME-style CRLF canonicalization to
// the content and the digest no longer matches the messageDigest signed
// attribute that smimesign/ietf-cms produced over the verbatim bytes,
// so end users following the README see a spurious verification failure.
func TestREADMEOpensslVerifyHasBinary(t *testing.T) {
	w := postPInfo(t, validPInfo())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q; want 200", w.Code, w.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	var readme []byte
	for _, f := range zr.File {
		if f.Name != "README.txt" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open README.txt: %v", err)
		}
		readme, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read README.txt: %v", err)
		}
		break
	}
	if len(readme) == 0 {
		t.Fatal("README.txt entry not found in zip")
	}
	// Find the openssl cms -verify command and confirm it carries -binary.
	if !bytes.Contains(readme, []byte("openssl cms -verify")) {
		t.Fatal("README.txt missing 'openssl cms -verify' snippet")
	}
	if !bytes.Contains(readme, []byte("-binary")) {
		t.Errorf("README.txt openssl example missing -binary flag; got:\n%s", readme)
	}
}

// TestPostMUDBodyTooLarge verifies that requests exceeding the body-size
// limit are rejected with 413 and that the handler does not perform any
// expensive crypto work.
func TestPostMUDBodyTooLarge(t *testing.T) {
	// A body larger than maxRequestBytes but still well-formed JSON
	// structure (the size comes from a giant Mudfile field).
	oversize := bytes.Repeat([]byte("A"), maxRequestBytes+1024)
	body := append([]byte(`{"Model":"x","Mudfile":"`), oversize...)
	body = append(body, []byte(`"}`)...)

	req := httptest.NewRequest(http.MethodPost, "/mudzip", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	newTestRouter().ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %q; want 413", w.Code, w.Body.String())
	}
}

// validPInfo returns a ProductInfo that passes validateProductInfo, so
// individual tests can mutate one field to exercise a single rule.
func validPInfo() ProductInfo {
	mudjson := `{"ietf-mud:mud":{"mud-version":1,"mud-url":"https://example.com/test.json"}}`
	return ProductInfo{
		Manufacturer: "ACME Supplies",
		Model:        "TestDevice",
		CountryCode:  "US",
		MudUrl:       "https://example.com/test.json",
		SerialNumber: "SN-0001",
		EmailAddress: "signer@example.com",
		Mudfile:      base64.StdEncoding.EncodeToString([]byte(mudjson)),
	}
}

func postPInfo(t *testing.T, p ProductInfo) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mudzip", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	newTestRouter().ServeHTTP(w, req)
	return w
}

// TestValidateProductInfoRejects exercises each validation rule on the
// /mudzip endpoint. Every case is expected to return 400 without invoking
// any of the crypto routines.
func TestValidateProductInfoRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(p *ProductInfo)
	}{
		{"empty Model", func(p *ProductInfo) { p.Model = "" }},
		{"Model with CRLF", func(p *ProductInfo) { p.Model = "x\r\ny" }},
		{"Model too long", func(p *ProductInfo) { p.Model = strings.Repeat("a", 65) }},
		{"empty Manufacturer", func(p *ProductInfo) { p.Manufacturer = "" }},
		{"Manufacturer with control char", func(p *ProductInfo) { p.Manufacturer = "ACME\x01" }},
		{"lowercase CountryCode", func(p *ProductInfo) { p.CountryCode = "us" }},
		{"3-char CountryCode", func(p *ProductInfo) { p.CountryCode = "USA" }},
		{"empty CountryCode", func(p *ProductInfo) { p.CountryCode = "" }},
		{"http MudUrl", func(p *ProductInfo) { p.MudUrl = "http://example.com/x.json" }},
		{"non-URL MudUrl", func(p *ProductInfo) { p.MudUrl = "not a url" }},
		{"empty MudUrl", func(p *ProductInfo) { p.MudUrl = "" }},
		{"bad EmailAddress", func(p *ProductInfo) { p.EmailAddress = "not-an-email" }},
		{"empty Mudfile", func(p *ProductInfo) { p.Mudfile = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPInfo()
			tc.mut(&p)
			w := postPInfo(t, p)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %q; want 400", w.Code, w.Body.String())
			}
		})
	}
}

// TestValidateProductInfoAccepts confirms the baseline ProductInfo built
// by validPInfo passes validation end-to-end (200 + zip body).
func TestValidateProductInfoAccepts(t *testing.T) {
	w := postPInfo(t, validPInfo())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q; want 200", w.Code, w.Body.String())
	}
}

// TestModelSanitizedForFilenames verifies that a Model containing
// characters that would be dangerous in a filename or HTTP header
// (slash, quote, space) is accepted but never appears verbatim in
// either the zip entry names or the Content-Disposition header.
// This guards against the CWE-22 / CWE-93 cases originally enforced by
// the modelRe regex: those characters are now sanitized rather than
// rejected, so the Model field can carry the free-form systeminfo text
// that the mudmaker UI produces.
func TestModelSanitizedForFilenames(t *testing.T) {
	p := validPInfo()
	p.Model = `../etc/pa"ss wd`

	w := postPInfo(t, p)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q; want 200", w.Code, w.Body.String())
	}

	cd := w.Header().Get("Content-Disposition")
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		t.Fatalf("ParseMediaType(%q): %v", cd, err)
	}
	fname := params["filename"]
	if fname == "" {
		t.Fatalf("Content-Disposition %q has no filename", cd)
	}
	if strings.ContainsAny(fname, `/\"`+" ") {
		t.Errorf("filename = %q contains unsafe character", fname)
	}
	if !strings.Contains(fname, "_") {
		t.Errorf("filename = %q expected to contain '_' from sanitization", fname)
	}

	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	for _, f := range zr.File {
		if strings.ContainsAny(f.Name, `/\"`+" ") {
			t.Errorf("zip entry name %q contains unsafe character", f.Name)
		}
	}
}
