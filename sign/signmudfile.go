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

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	. "mudmaker.org/mudcerts"
	"os"
	"regexp"
)

/*
 signmudfile takes as input a key, a signer, ad one or more files, and
 generates a cms signature, by appending .p7s to the file.  Other file
 extensions are dropped.

 Usage:

  signmudfile [flags] [path ...]
  
  -cert string
        Name of file containing signing cert (default "signer.pem")
  -key string
        Signer key (default "signer.key")

*/
func main() {
	certfile := flag.String("cert", "signer.pem",
		"Name of file containing signing cert")
	keyfile := flag.String("key", "signer.key", "Signer key")
	flag.Parse()
	// read in cert and key
	pemfile, err := os.ReadFile(*certfile)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(pemfile)
	if block == nil {
		log.Fatal("No certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	pemfile, err = os.ReadFile(*keyfile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ = pem.Decode(pemfile)
	if block == nil {
		log.Fatal("No key found")
	}

	key, _ := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	if flag.NArg() == 0 {
		log.Fatal("No files to sign.")
	}

	re := regexp.MustCompile("\\..*$")
	for _, fn := range flag.Args() {
		var newfn = re.ReplaceAllLiteralString(fn, "") + ".p7s"
		mudfile, err := os.ReadFile(fn)
		if err != nil {
			log.Fatal(err)
		}
		der, err := SignMudFile(string(mudfile), cert, key)
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile(newfn, der, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}
}
