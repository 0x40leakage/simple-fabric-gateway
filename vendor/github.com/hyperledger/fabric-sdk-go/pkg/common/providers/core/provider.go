/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package core

//CryptoSuiteConfig contains sdk configuration items for cryptosuite.
type CryptoSuiteConfig interface {
	IsSecurityEnabled() bool
	SecurityAlgorithm() string
	SecurityLevel() int
	SecurityProvider() string
	SecurityPlugin() string
	SoftVerify() bool
	SecurityProviderLibPath() string
	SecurityProviderPin() string
	SecurityProviderLabel() string
	SecurityProviderAlgorithm() string
	KeyStorePath() string

	// configuration items for GM
	SecurityImplType() string
	SecurityLibrary() string
	SecurityIP() string
	SecurityPort() string
	SecurityPassword() string
}

// Providers represents the SDK configured core providers context.
type Providers interface {
	CryptoSuite() CryptoSuite
	SigningManager() SigningManager
}

//ConfigProvider provides config backend for SDK
type ConfigProvider func() ([]ConfigBackend, error)

//ConfigBackend backend for all config types in SDK
type ConfigBackend interface {
	Lookup(key string) (interface{}, bool)
}
