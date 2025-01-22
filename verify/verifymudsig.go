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
verifymudsig verifies a MUD signature on a file, with a given cert set.

Usage:

  verifymudsig [flags] {mud file to be verified}

The flags are as follows:

  -cert string
        Name of file containing one or more signing certs
        (default "signer.pem")
  -sig string
        Name of file containing DER signature. (default "mudfile.p7s")

*/
import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	cms "github.com/github/smimesign/ietf-cms"
)

func main() {
	certfile := flag.String("cert", "signer.pem",
		"Name of file containing one or more certificates, including a trust anchor (CA Cert)")
	sigfile := flag.String("sig", "mudfile.p7s",
		"name of file containing DER signature.")
	flag.Parse()
	// read in certs
	pemfile, err := os.ReadFile(*certfile)
	if err != nil {
		log.Fatal(err)
	}
	block, rest := pem.Decode(pemfile)

	if block == nil {
		log.Fatal("no certs available")
	}

	opts := x509.VerifyOptions{
		Roots:     x509.NewCertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	for (rest != nil) && (block != nil) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		opts.Roots.AddCert(cert)
		block, rest = pem.Decode(rest)
	}

	sig, err := os.ReadFile(*sigfile)
	if err != nil {
		log.Fatal(err)
	}

	if flag.NArg() != 1 {
		log.Fatal("No data file specified: provide filename of mud file to be verified.")
	}

	mudfile, err := os.ReadFile(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}

	sd, err := cms.ParseSignedData(sig)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	if _, err := sd.VerifyDetached(mudfile, opts); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Ok.")
}
