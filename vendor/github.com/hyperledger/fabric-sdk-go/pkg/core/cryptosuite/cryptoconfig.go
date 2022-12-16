/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptosuite

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config/lookup"
	"github.com/hyperledger/fabric-sdk-go/pkg/util/cryptocfg"
	"github.com/hyperledger/fabric-sdk-go/pkg/util/pathvar"
	"github.com/spf13/cast"
)

const (
	defEnabled       = true
	defHashAlgorithm = "SHA2"
	defLevel         = 256
	defProvider      = "SW"
	defSoftVerify    = true

	defX509Plugin = "ccsgm"
)

//ConfigFromBackend returns CryptoSuite config implementation for given backend
func ConfigFromBackend(coreBackend ...core.ConfigBackend) core.CryptoSuiteConfig {
	return &Config{backend: lookup.New(coreBackend...)}
}

// Config represents the crypto suite configuration for the client
type Config struct {
	backend *lookup.ConfigLookup
}

// IsSecurityEnabled config used enable and disable security in cryptosuite
// !!! TODO
func (c *Config) IsSecurityEnabled() bool {
	val, ok := c.backend.Lookup("client.BCCSP.security.enabled")
	if !ok {
		return defEnabled
	}
	return cast.ToBool(val)
}

// SecurityAlgorithm returns cryptoSuite config hash algorithm
func (c *Config) SecurityAlgorithm() string {
	var fieldPath string
	switch c.SecurityProvider() {
	case "sw":
		fieldPath = "client.BCCSP.SW.Hash"
	case "pkcs11":
		fieldPath = "client.BCCSP.PKCS11.Hash"
	default:
		fieldPath = "client.BCCSP.SW.Hash"
	}

	val, ok := c.backend.Lookup(fieldPath)
	if !ok {
		return defHashAlgorithm
	}
	return cast.ToString(val)
}

// SecurityLevel returns cryptSuite config security level
func (c *Config) SecurityLevel() int {
	var fieldPath string
	switch c.SecurityProvider() {
	case "sw":
		fieldPath = "client.BCCSP.SW.Security"
	case "pkcs11":
		fieldPath = "client.BCCSP.PKCS11.Security"
	default:
		fieldPath = "client.BCCSP.SW.Security"
	}

	val, ok := c.backend.Lookup(fieldPath)
	if !ok {
		return defLevel
	}
	return cast.ToInt(val)
}

// SecurityProvider provider SW, PKCS11 or SDF
func (c *Config) SecurityProvider() string {
	val, ok := c.backend.Lookup("client.BCCSP.Default")
	if !ok {
		return strings.ToLower(defProvider)
	}
	return strings.ToLower(cast.ToString(val))
}

//SecurityPlugin plugin std or ccsgm
// !!! TODO
func (c *Config) SecurityPlugin() string {
	// val, ok := c.backend.Lookup("client.BCCSP.security.x509PluginType")
	// if !ok {
	// 	return strings.ToLower(defX509Plugin)
	// }
	return strings.ToLower(defX509Plugin)
}

// SoftVerify flag
// !!! TODO
func (c *Config) SoftVerify() bool {
	val, ok := c.backend.Lookup("client.BCCSP.security.softVerify")
	if !ok {
		return defSoftVerify
	}
	return cast.ToBool(val)
}

// SecurityProviderLibPath will be set only if provider is PKCS11
// !!! TODO
func (c *Config) SecurityProviderLibPath() string {
	configuredLibs := c.backend.GetString("client.BCCSP.PKCS11.Library")
	libPaths := strings.Split(configuredLibs, ",")
	logger.Debugf("Configured BCCSP Lib Paths %s", libPaths)
	var lib string
	for _, path := range libPaths {
		if _, err := os.Stat(strings.TrimSpace(path)); err == nil || os.IsExist(err) {
			lib = strings.TrimSpace(path)
			break
		}
	}
	if lib != "" {
		logger.Debugf("Found softhsm library: %s", lib)
	} else {
		logger.Debug("Softhsm library was not found")
	}
	return lib
}

//SecurityProviderPin will be set only if provider is PKCS11
func (c *Config) SecurityProviderPin() string {
	return c.backend.GetString("client.BCCSP.PKCS11.Pin")
}

//SecurityProviderLabel will be set only if provider is PKCS11
func (c *Config) SecurityProviderLabel() string {
	return c.backend.GetString("client.BCCSP.PKCS11.Label")
}

func (c *Config) SecurityProviderAlgorithm() string {
	sa := c.backend.GetString("client.BCCSP.PKCS11.SignatureAlgorithm")

	// !!! TODO temporary converter, REMOVE LATER
	if sa == cryptocfg.SignatureAlgorithmGM {
		sa = "GM"
	} else {
		sa = "SW"
	}
	return sa
}

// KeyStorePath returns the keystore path used by BCCSP
// !!! TODO
func (c *Config) KeyStorePath() string {
	keystorePath := pathvar.Subst(c.backend.GetString("client.credentialStore.cryptoStore.path"))
	return filepath.Join(keystorePath, "keystore")
}

func (c *Config) SecurityImplType() string {
	return c.backend.GetString("client.BCCSP.SW.Vendor")
}

func (c *Config) SecurityLibrary() string {
	return c.backend.GetString("client.BCCSP.SW.XIN_AN.Library")
}

func (c *Config) SecurityIP() string {
	return c.backend.GetString("client.BCCSP.SW.XIN_AN.IP")
}

func (c *Config) SecurityPort() string {
	return c.backend.GetString("client.BCCSP.SW.XIN_AN.Port")
}

func (c *Config) SecurityPassword() string {
	return c.backend.GetString("client.BCCSP.SW.XIN_AN.Password")
}
