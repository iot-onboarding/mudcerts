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
	"bytes"
	"encoding/pem"
	"fmt"
)

// MakePEM returns a PEM-encoded buffer for the given DER bytes and
// block type. It returns an error if pem.Encode fails (which in
// practice only happens on a programmer error such as a bad block
// header), so callers should still check err.
func MakePEM(inBytes []byte, pemtype string) (*bytes.Buffer, error) {
	outPEM := new(bytes.Buffer)
	if err := pem.Encode(outPEM, &pem.Block{
		Type:  pemtype,
		Bytes: inBytes,
	}); err != nil {
		return nil, fmt.Errorf("pem encode %s: %w", pemtype, err)
	}
	return outPEM, nil
}
