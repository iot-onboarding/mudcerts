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

// Package mudcerts provides a set of functions to generate certificates,
// keys, and signatures relating to MUD files and MUD-enabled devices.
package mudcerts

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// certSerial returns a serial number suitable for a certificate.
func certSerial() (*big.Int, error) {
	serNum, err := rand.Int(rand.Reader, big.NewInt(9223372036854))
	if err != nil {
		return big.NewInt(0), fmt.Errorf("%s", err)
	}
	return serNum, nil
}

// certSKI returns a randomly generated subject key identifier.
func certSKI() ([]byte, error) {
	ski, err := rand.Int(rand.Reader, big.NewInt(9223372036854775807))
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	return ski.Bytes(), nil
}
