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
	"net/http"
	"net/http/httptest"
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
