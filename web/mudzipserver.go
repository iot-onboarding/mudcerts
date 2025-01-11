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
	"github.com/gin-gonic/gin"
	"log"
	. "mudmaker.org/mudcerts"
	"net/http"
)

// postMUD processes a POST on /mudzip and returns a zip file.
func postMUD(c *gin.Context) {
	var pinfo ProductInfo

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

	mudjson, err := base64.StdEncoding.DecodeString(pinfo.Mudfile)
	mudsigncert, err := x509.ParseCertificate(mudsigner)
	mudsig, err := SignMudFile(string(mudjson), mudsigncert, mudsignerPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	var files = []struct {
		Name, Body string
	}{
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
	router.Run(":8085")
}
