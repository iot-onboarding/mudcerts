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

package mudcerts

import (
	"crypto/x509"
	"testing"
)

// GenCA_test tests the GenCA function by providing a ProductInfo
// struct and parsing the results.
func TestGenCA(t *testing.T) {
	pinfo := ProductInfo{
		Manufacturer: "Test CA",
		CountryCode:  "US",
		SerialNumber: "12345",
	}

	cabytes, _, err := GenCA(pinfo)
	if err != nil {
		t.Fatalf(`GenCA() failed with %v, want CAcert, CA Key, nil`, err)
	}
	cacert, err := x509.ParseCertificate(cabytes)
	if err != nil {
		t.Fatalf(`GenCA() did not generate a valid certiticate %v`, err)
	}
	if (cacert.Subject.CommonName != cacert.Issuer.CommonName) &&
		(cacert.Subject.Organization[0] != "Test CA") {
		t.Fatalf(`GenCA() wanted "Test CA", got %s`,
			cacert.Subject.Organization)
	}
}
