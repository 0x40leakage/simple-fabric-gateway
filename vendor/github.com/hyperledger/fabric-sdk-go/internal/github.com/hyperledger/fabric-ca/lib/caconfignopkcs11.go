// +build pkcs11

package lib

import "strings"

func (c CAConfig) IsGMConfig() bool {
	if strings.ToUpper(c.CSP.ProviderName) == "GM" {
		return true
	}
	return false
}

func (c *Client) IsGMConfig() bool {
	if strings.ToUpper(c.Config.Opts.ProviderName) == "GM" { //||
		//(strings.ToUpper(c.Config.CSP.ProviderName) == "PKCS11" && c.Config.CSP.Pkcs11Opts.Algorithm == "GM") {
		return true
	}
	return false
}
