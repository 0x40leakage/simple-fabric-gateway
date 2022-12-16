package cryptocfg

const (
	swGMVendorXinAn = "xin_an"
	swGMVendorCCSGM = "ccsgm"
)

var validSWVendors = []string{swGMVendorXinAn, swGMVendorCCSGM}

func IsValidSWGMVendor(vendor string) bool {
	for _, v := range validSWVendors {
		if v == vendor {
			return true
		}
	}
	return false
}

const (
	SignatureAlgorithmECDSA = "ECDSAWithSHA256"
	SignatureAlgorithmGM    = "SM2WithSM3"
)

// !!! TODO replace all bccsp hardcoded strings
