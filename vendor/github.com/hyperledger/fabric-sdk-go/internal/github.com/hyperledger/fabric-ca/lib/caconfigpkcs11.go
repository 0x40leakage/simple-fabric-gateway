// +build !pkcs11

package lib

import "strings"

func (c CAConfig) IsGMConfig() bool {
	if (strings.ToUpper(c.CSP.ProviderName) == "GM") ||
		(strings.ToUpper(c.CSP.ProviderName) == "PKCS11" && c.CSP.Pkcs11Opts.Algorithm == "GM") ||
		strings.ToUpper(c.CSP.ProviderName) == "SDF" {
		return true
	}
	return false
}

func (c *Client) IsGMConfig() bool {
	if strings.ToUpper(c.Config.Opts.ProviderName) == "GM" ||
		(strings.ToUpper(c.Config.Opts.ProviderName) == "PKCS11" && c.Config.Opts.Pkcs11Opts.Algorithm == "GM") ||
		strings.ToUpper(c.Config.Opts.ProviderName) == "SDF" {
		return true
	}
	return false
}
