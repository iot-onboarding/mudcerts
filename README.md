# MUDCERTs library, web interface, and CLI interface

![image of mud and a lock](https://github.com/iot-onboarding/mudcerts/blob/main/mudcerts.png?raw=true)

Welcome to MUDCERTS!  This repository contains a golang library and some
example uses to sign and verify certificates that contain the
appropriate extensions for use with devices that implement
[Manufacturer Usage Descriptions](https://www.rfc-editor.org/rfc/rfc8520.html).  This code is used as part of [mudmaker.org](https://mudmaker.org) to build mudfiles and to generate **demonstration** certificates.

Copyright Cisco Systems and/or its affiliates, 2024.\
All Rights Reserved.

But don’t be scared.  There's an Apache license waiting for you.  Contributions more than welcome.  See COPYRIGHT, CONTRIBUTING, and SECURITY files for respective details.

## The mudcerts library

### Importing the library

import (
		"github.com/iot-onboarding/mudcerts"
)

## Index

[func GenCA(ProductInfo) ([]byte, *ecdsa.PrivateKey, error)](#func-genca)\
[func MakeMUDcert(ProductInfo, *x509.Certificate, *ecdsa.PrivateKey) ([]byte,*ecdsa.PrivateKey,error)](#func-makemudcert)\
[func MakePEM([]byte, string) *bytes.Buffer](#func-makepem)\
[func MakeSignerCert(p ProductInfo, ca *x509.Certificate, caPrivKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error)](#func-makesignercert)\
[func SignMudFile(mudfile string, signerCert *x509.Certificate,
        certkey *ecdsa.PrivateKey) ([]byte, error)](#func-signmudfile) \
[type ProductInfo](#type-productinfo)

### Examples

[mkmudcerts](#mkmudcerts)\
[signmudfile](#signmudfile)\
[mudzipserver](#mudzipserver)\
[verifymudsig](#verifymudsig)

[TODO](#todo)

## Functions

### func GenCA

> func GenCA(ProductInfo) ([]byte, *ecdsa.PrivateKey, error)

Returns a cert in the byte array, its associate private key, or an error.

### func MakeMUDcert

> func MakeMUDcert(ProductInfo, *x509.Certificate, *ecdsa.PrivateKey) ([]byte,*ecdsa.PrivateKey,error)

Returns a product cert with appropriate MUD extensions, an associated private key, or an error.  Requires the output from GenCA.

### func MakePEM
> func MakePEM([]byte, string) *bytes.Buffer

Generates a PEM file with the header passed as a second argument.

### func MakeSignerCert
> MakeSignerCert(p ProductInfo, ca *x509.Certificate, caPrivKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error)

### func SignMudFile
> SignMudFile(mudfile string, signerCert *x509.Certificate, certkey *ecdsa.PrivateKey) ([]byte, error)

Takes as input 

## Types

### type ProductInfo

```
type ProductInfo struct {
	Manufacturer, Model, CountryCode string
 	MudUrl, SerialNumber, Mudfile    string
 	EmailAddress                     string
}
```

## Program Examples
### mkmudcerts

```
Usage: mkmudcerts
  -cc string
    	Country Code of Manufacturer (default "US")
  -mfg string
    	Name of Manufacturer (default "ACME Supplies")
  -mod string
    	Device Model (default "Hornblower 2000")
  -mudurl string
    	URL for MUDfile (default "https://...")
  -ser string
    	A device Serial Number (default "SN12345")
```
Generates a CA cert, a CA private key, a cert with MUD attributes, and an associated private key.

### signmudfile

```
Usage: signmudfile
  -cert string
    	Name of file containing signing cert (default "signer.pem")
  -key string
    	Signer key (default "signer.key")
```

Signs a MUD file, generating a detached cms signature with the output ending in .p7s of the input.

### verifymudsig

Usage: verifymudsig
  -cert string
    	Name of file containing one or more signing certs (default "signer.pem")
  -sig string
    	name of file containing DER signature. (default "mudfile.p7s")

### mudzipserver

Listens on http://localhost:8085/.


#### POST mudzip

Input: JSON version of ProductInfo

Returns: a zip file containing all the certs and a signed MUD file.

## TODO

* Currently only ECDSA certs with P256 are supported.
* Test cases.
