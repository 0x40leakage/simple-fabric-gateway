/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package bccsp

const (
	SM2 = "SM2"
	SM3 = "SM3"
	SM4 = "SM4"
)

type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type XinAnSM2KeyGenOpts struct {
	Temporary bool
	DN        string
	Alias     string
}

func (opts *XinAnSM2KeyGenOpts) Algorithm() string {
	return SM2
}

func (opts *XinAnSM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *XinAnSM2KeyGenOpts) GetDN() string {
	return opts.DN
}

func (opts *XinAnSM2KeyGenOpts) GetAlias() string {
	return opts.Alias
}

type XinAnSM2KeyGenOpts1 struct {
	Temporary bool
	Alias     string
	Cert      []byte
}

func (opts *XinAnSM2KeyGenOpts1) Algorithm() string {
	return SM2
}

func (opts *XinAnSM2KeyGenOpts1) Ephemeral() bool {
	return opts.Temporary
}

func (opts *XinAnSM2KeyGenOpts1) GetAlias() string {
	return opts.Alias
}

func (opts *XinAnSM2KeyGenOpts1) GetCert() []byte {
	return opts.Cert
}

type SM2PublicKeyImportOpts struct {
	Temporary bool
}

func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyGenKEKOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4KeyGenKEKOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenKEKOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyImportOpts struct {
	Temporary bool
}

func (opts *SM4KeyImportOpts) Algorithm() string {
	return SM4
}

func (opts *SM4KeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4EncKeyImportOpts struct {
	Temporary bool
}

func (opts *SM4EncKeyImportOpts) Algorithm() string {
	return SM4
}

func (opts *SM4EncKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// sm3 hash opts
type SM3HashOpts struct {
}

func (opts *SM3HashOpts) Algorithm() string {
	return SM3
}

type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type X509SM2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *X509SM2PublicKeyImportOpts) Algorithm() string {
	return X509Certificate
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *X509SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
