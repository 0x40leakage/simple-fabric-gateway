package xinan

import (
	"bytes"
	"encoding/asn1"
)

func asn1Bytes(src []byte) []byte {
	if len(src) <= 2 || src[0] == 30 {
		return src
	}
	var tmp []byte
	dst := make([]byte, len(src))
	dst[0] = src[0]
	tmp = src[2:]
	j := 2
	for len(tmp) > 0 {
		if len(tmp) < 4 {
			return src
		}
		if tmp[0] == 2 && ((tmp[2] == 0 && tmp[3]&0x80 == 0) || (tmp[2] == 0xff && tmp[3]&0x80 == 0x80)) {
			dst[j] = tmp[0]
			dst[j+1] = tmp[1] - 1
			copy(dst[j+2:], tmp[3:int(tmp[1])+2])
			j = j + int(tmp[1]) + 1
			tmp = tmp[2+tmp[1]:]
		} else {
			copy(dst[j:], tmp[:int(tmp[1])+2])
			j = j + int(tmp[1]) + 2
			tmp = tmp[2+tmp[1]:]
		}
	}
	dst[1] = byte(j - 2)
	if bytes.Equal(src, dst[:j]) {
		return src
	}
	return asn1Bytes(dst[:j])
}

func signatureBytesForXinan(src []byte) []byte {
	if len(src) > 70 {
		return src
	}
	dst := make([]byte, 72)
	dst[0] = src[0]
	tmp := src[2:]
	j := 2
	for len(tmp) > 0 {
		if len(tmp) < 4 {
			return src
		}
		if tmp[0] == 2 && tmp[1] < 32 {
			dst[j] = tmp[0]
			dst[j+1] = 32
			copy(dst[j+34-int(tmp[1]):j+34], tmp[2:int(tmp[1])+2])
			j = j + 34
			tmp = tmp[2+tmp[1]:]
		} else {
			copy(dst[j:], tmp[:int(tmp[1])+2])
			j = j + int(tmp[1]) + 2
			tmp = tmp[2+tmp[1]:]
		}
	}
	dst[1] = byte(j - 2)
	return dst[:j]
}

func asn1UnmarshalWithCheck(b []byte, val interface{}) (rest []byte, err error) {
	if rest, err := asn1.Unmarshal(b, val); err == nil {
		return rest, nil
	}
	return asn1.Unmarshal(asn1Bytes(b), val)
}
