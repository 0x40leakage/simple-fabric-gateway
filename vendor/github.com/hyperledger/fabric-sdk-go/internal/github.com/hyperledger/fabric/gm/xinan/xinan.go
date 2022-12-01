package xinan

/*
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl
#cgo openbsd LDFLAGS: -ldl
#cgo freebsd LDFLAGS: -ldl

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "xinan.h"

// New initializes a ctx and fills the symbol table.
struct xinAnCtx *NewXinAnForSDK(const char *module)
{
	struct xinAnCtx *c = calloc(1, sizeof(struct xinAnCtx));
	c->handle = dlopen(module, RTLD_LAZY);
	if (c->handle == NULL) {
		free(c);
		return NULL;
	}
	c->api = (XinAnAPI*)calloc(1, sizeof(XinAnAPI));
	return c;
}

void DestroyXinANForSDK(struct xinAnCtx *c)
{
	if (!c) {
		return;
	}
	if (c->handle == NULL) {
		return;
	}
	if (dlclose(c->handle) < 0) {
		return;
	}
	free(c);
}

int ConnToNetSignForSDK(struct xinAnCtx * c, char* ip, int port, char* passwd, int *sockFd){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->connToNetSign == NULL){
		c->api->connToNetSign = (int (*)(char *, int, char *, int *))dlsym(c->handle,"ConnToNetSign");
	}
	if(c->api->connToNetSign == NULL){
		return NO_API_ERROR;
	}
	return c->api->connToNetSign(ip, port, passwd, sockFd);
}

int DiscFromNetSignForSDK(struct xinAnCtx * c, int sockFd){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->discFromNetSign == NULL){
		c->api->discFromNetSign = (int (*)(int))dlsym(c->handle,"DiscFromNetSign");
	}
	if(c->api->discFromNetSign == NULL){
		return NO_API_ERROR;
	}
	return c->api->discFromNetSign(sockFd);
}

char* NS_GetVersionForSDK(struct xinAnCtx * c){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NULL;
	}
	if(c->api->getVersion == NULL){
		c->api->getVersion = (char* (*)())dlsym(c->handle,"NS_GetVersion");
	}
	if(c->api->getVersion == NULL){
		return NULL;
	}
	return c->api->getVersion();
}

int UploadCertForSDK(struct xinAnCtx * c, int sockFd, unsigned char* cert, int iCertLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->uploadCert == NULL){
		c->api->uploadCert = (int (*)(int, unsigned char*, int))dlsym(c->handle,"UploadCert");
	}
	if(c->api->uploadCert == NULL){
		return NO_API_ERROR;
	}
	return c->api->uploadCert(sockFd, cert, iCertLen);
}

int IsCertExistForSDK(struct xinAnCtx * c, int sockFd, char* signCertDN){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->certExist == NULL){
		c->api->certExist = (int (*)(int, char*))dlsym(c->handle,"IsCertExist");
	}
	if(c->api->certExist == NULL){
		return NO_API_ERROR;
	}
	return c->api->certExist(sockFd, signCertDN);
}

int INS_KPLGenP10ReqForSDK(struct xinAnCtx * c,int sockFd,char* certDN,char* keyID,
	char* keyType, int isCover, unsigned char* p10Data, unsigned int *p10Len){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->KPLGenP10Req == NULL){
		c->api->KPLGenP10Req = (int (*)(int, char*, char*, char*, int, unsigned char*, unsigned int *))dlsym(c->handle,"INS_KPLGenP10Req");
	}
	if(c->api->KPLGenP10Req == NULL){
		return NO_API_ERROR;
	}
	return c->api->KPLGenP10Req(sockFd, certDN, keyID, keyType, isCover, p10Data, p10Len);
}

int INS_KPLImportCertForSDK(struct xinAnCtx * c,int sockFd, char* keyID, unsigned char* certData, unsigned int certLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->KPLImportCert == NULL){
		c->api->KPLImportCert = (int (*)(int, char*, unsigned char*, unsigned int))dlsym(c->handle,"INS_KPLImportCert");
	}
	if(c->api->KPLImportCert == NULL){
		return NO_API_ERROR;
	}
	return c->api->KPLImportCert(sockFd, keyID, certData, certLen);
}

int INS_RawSignDataForSDK(struct xinAnCtx * c,int sockFd, unsigned char* data,
				int iLen,char* signCertDN, char *digestAlg, int flag,
				unsigned char* crypto, int* iCryptoLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->rawSignData == NULL){
		c->api->rawSignData = (int (*)(int, unsigned char*, int, char*, char *, int, unsigned char*, int*))dlsym(c->handle,"INS_RawSignData");
	}
	if(c->api->rawSignData == NULL){
		return NO_API_ERROR;
	}
	return c->api->rawSignData(sockFd, data, iLen, signCertDN, digestAlg, flag, crypto, iCryptoLen);
}

int INS_RawVerifyDataForSDK(struct xinAnCtx * c,int sockFd, unsigned char* data,
				int iLen, char* signCertDN, char *digestAlg, int flag,
				  unsigned char* crypto, int iCryptoLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->rawVerifyData == NULL){
		c->api->rawVerifyData = (int (*)(int, unsigned char*, int, char*, char *, int, unsigned char*, int))dlsym(c->handle,"INS_RawVerifyData");
	}
	if(c->api->rawVerifyData == NULL){
		return NO_API_ERROR;
	}
	return c->api->rawVerifyData(sockFd, data, iLen, signCertDN, digestAlg, flag, crypto, iCryptoLen);
}

int INS_RawVerifyWithCertForSDK(struct xinAnCtx * c,int sockFd, unsigned char* data, int iLen, unsigned char* x509cert, int x509Len,
		char *digestAlg, int flag   ,unsigned char* crypto, int iCryptoLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->rawVerifyWithCert == NULL){
		c->api->rawVerifyWithCert = (int (*)(int, unsigned char*, int, unsigned char*, int, char *, int, unsigned char*, int))dlsym(c->handle,"INS_RawVerifyWithCert");
	}
	if(c->api->rawVerifyWithCert == NULL){
		return NO_API_ERROR;
	}
	return c->api->rawVerifyWithCert(sockFd, data, iLen, x509cert, x509Len, digestAlg, flag, crypto, iCryptoLen);

}
int INS_RawEncryptForSDK(struct xinAnCtx * c,int sockFd, unsigned char* data, int iLen,
				   char* encCertDN, int flag, unsigned char* crypto, int* iCryptoLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->rawEncrypt == NULL){
		c->api->rawEncrypt = (int (*)(int, unsigned char*, int, char*, int, unsigned char*, int*))dlsym(c->handle,"INS_RawEncrypt");
	}
	if(c->api->rawEncrypt == NULL){
		return NO_API_ERROR;
	}
	return c->api->rawEncrypt(sockFd, data, iLen, encCertDN, flag, crypto, iCryptoLen);
}

int INS_RawEncryptWithCertForSDK(struct xinAnCtx * c,int sockFd, unsigned char* data, int iLen, unsigned char* x509cert,
			int x509Len, int flag, unsigned char* crypto, int* iCryptoLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->rawEncryptWithCert == NULL){
		c->api->rawEncryptWithCert = (int (*)(int, unsigned char*, int, unsigned char*, int, int, unsigned char*, int*))dlsym(c->handle,"INS_RawEncryptWithCert");
	}
	if(c->api->rawEncryptWithCert == NULL){
		return NO_API_ERROR;
	}
	return c->api->rawEncryptWithCert(sockFd, data, iLen, x509cert, x509Len, flag, crypto, iCryptoLen);
}

int INS_RawDecryptForSDK(struct xinAnCtx * c,int sockFd,unsigned char* crypto, int iCryptoLen,
				   char* encCertDN, int flag, unsigned char* data, int *iLen ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->rawDecrypt == NULL){
		c->api->rawDecrypt = (int (*)(int, unsigned char*, int, char*, int, unsigned char*, int*))dlsym(c->handle,"INS_RawDecrypt");
	}
	if(c->api->rawDecrypt == NULL){
		return NO_API_ERROR;
	}
	return c->api->rawDecrypt(sockFd, crypto, iCryptoLen, encCertDN, flag, data, iLen);
}

int INS_HashDataForSDK(struct xinAnCtx * c,int sockFd, char *digestAlg,
				  unsigned char* pMsg, int pMsgLen, unsigned char* pDigest,int* pDigestLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->hashData == NULL){
		c->api->hashData = (int (*)(int, char*, unsigned char*, int, unsigned char*, int*))dlsym(c->handle,"INS_HashData");
	}
	if(c->api->hashData == NULL){
		return NO_API_ERROR;
	}
	return c->api->hashData(sockFd, digestAlg, pMsg, pMsgLen, pDigest, pDigestLen);
}

int INS_GenRandomForSDK(struct xinAnCtx * c,int sockFd, unsigned char* data, int iLen ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->genRandom == NULL){
		c->api->genRandom = (int (*)(int, unsigned char*, int))dlsym(c->handle,"INS_GenRandom");
	}
	if(c->api->genRandom == NULL){
		return NO_API_ERROR;
	}
	return c->api->genRandom(sockFd, data, iLen);
}

int INS_EncryptWithKeyForSDK(struct xinAnCtx * c,int sockFd, const unsigned char * key, int len, SymmEncryptParam *encParam,
				 const unsigned char* data, int iLen,	unsigned char* crypto, int * iCryptoLen ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->encryptWithKey == NULL){
		c->api->encryptWithKey = (int (*)(int, const unsigned char*, int, SymmEncryptParam *,
				const unsigned char *, int, unsigned char *, int *))dlsym(c->handle,"INS_EncryptWithKey");
	}
	if(c->api->encryptWithKey == NULL){
		return NO_API_ERROR;
	}
	return c->api->encryptWithKey(sockFd, key, len, encParam, data, iLen, crypto, iCryptoLen);
}

int INS_DecryptWithKeyForSDK(struct xinAnCtx * c,int sockFd, const unsigned char * key, int len, SymmEncryptParam *decParam,
				  const unsigned char* crypto, int iCryptoLen, unsigned char* data, int *iLen ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->decryptWithKey == NULL){
		c->api->decryptWithKey = (int (*)(int, const unsigned char*, int, SymmEncryptParam *,
				const unsigned char *, int, unsigned char *, int *))dlsym(c->handle,"INS_DecryptWithKey");
	}
	if(c->api->decryptWithKey == NULL){
		return NO_API_ERROR;
	}
	return c->api->decryptWithKey(sockFd, key, len, decParam, crypto, iCryptoLen,data, iLen);

}

int INS_EncryptWithKeyIDForSDK(struct xinAnCtx * c,int sockFd, char* szKeyID, SymmEncryptParam *encParam,
						 unsigned char* data, int iLen, unsigned char* crypto, int * iCryptoLen ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->encryptWithKeyId == NULL){
		c->api->encryptWithKeyId = (int (*)(int, char*, SymmEncryptParam *,
				unsigned char *, int, unsigned char *, int *))dlsym(c->handle,"INS_EncryptWithKeyID");
	}
	if(c->api->encryptWithKeyId == NULL){
		return NO_API_ERROR;
	}
	return c->api->encryptWithKeyId(sockFd, szKeyID, encParam, data, iLen, crypto, iCryptoLen);
}

int INS_DecryptWithKeyIDForSDK(struct xinAnCtx * c,int sockFd,char* szKeyID, SymmEncryptParam *decParam,
						 unsigned char* crypto, int iCryptoLen, unsigned char* data, int *iLen ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->decryptWithKeyId == NULL){
		c->api->decryptWithKeyId = (int (*)(int, char*, SymmEncryptParam *,
				unsigned char *, int, unsigned char *, int *))dlsym(c->handle,"INS_DecryptWithKeyID");
	}
	if(c->api->decryptWithKeyId == NULL){
		return NO_API_ERROR;
	}
	return c->api->decryptWithKeyId(sockFd, szKeyID, decParam, crypto, iCryptoLen, data, iLen);
}

void generateSymmForSDK(SymmEncryptParam* symm, unsigned char* iv)
{
	strcpy(symm->Alg, "SM4");
	symm->mode = INS_PADDING_PKCS7 | INS_MODE_CBC;
	memcpy(&(symm->iv[0]),iv,16);
	symm->ivLen = 16;
}

unsigned char * NewUcharForXinanForSDK(int len){
	unsigned char * p;
	p = malloc(sizeof(unsigned char)*len);
	return p;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const SM4_LEN = 16

type ctx struct {
	ctx *C.struct_xinAnCtx
}

// stubData is a persistent nonempty byte array used by cMessage.
var stubData = []byte{0}

// cMessage returns the pointer/length pair corresponding to data.
func cMessage(data []byte) *C.uchar {
	l := len(data)
	if l == 0 {
		// &data[0] is forbidden in this case, so use a nontrivial array instead.
		data = stubData
	}
	return (*C.uchar)(unsafe.Pointer(&data[0]))
}

func newCtx(module string) *ctx {
	c := new(ctx)
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))
	c.ctx = C.NewXinAnForSDK(mod)
	if c.ctx == nil {
		return nil
	}
	return c
}
func (c *ctx) destroy() {
	C.DestroyXinANForSDK(c.ctx)
}

func (c *ctx) connToNetSign(serverip string, port int32, password string) (int32, error) {
	var sfd C.int
	ip := C.CString(serverip)
	defer C.free(unsafe.Pointer(ip))
	psw := C.CString(password)
	defer C.free(unsafe.Pointer(psw))
	ret := C.ConnToNetSignForSDK(c.ctx, ip, C.int(port), psw, &sfd)
	if ret != 0 {
		return 0, fmt.Errorf("connect to server failed, ret = %d", int32(ret))
	}
	return int32(sfd), nil
}

func (c *ctx) discFromNetSign(sockFd int32) error {
	ret := C.DiscFromNetSignForSDK(c.ctx, C.int(sockFd))
	if ret != 0 {
		return fmt.Errorf("disconnect to server %d failed, ret = %d", sockFd, ret)
	}
	return nil
}

func (c *ctx) getServerVersion() string {
	v := C.NS_GetVersionForSDK((c.ctx))
	defer C.free(unsafe.Pointer(v))
	return C.GoString(v)
}

func (c *ctx) uploadCert(sockFd int32, dn string, cert []byte) error {
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))
	ret := C.IsCertExistForSDK(c.ctx, C.int(sockFd), cdn)
	if ret == 0 {
		//不存在
		ret = C.UploadCertForSDK(c.ctx, C.int(sockFd), cMessage(cert), C.int(len(cert)))
		if ret != 0 {
			return fmt.Errorf("upload cert failed for %d", ret)
		}
	}
	return nil
}

func (c *ctx) iNS_KPLGenP10Req(sockFd int32, dn string, KeyID string) ([]byte, error) {
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))

	keyType := "SM2"
	ckeyType := C.CString(keyType)
	defer C.free(unsafe.Pointer(ckeyType))

	ckeyID := C.CString(KeyID)
	defer C.free(unsafe.Pointer(ckeyID))

	p10Data := C.NewUcharForXinanForSDK(1024)
	defer C.free(unsafe.Pointer(p10Data))
	p10DataLen := (C.uint)(1024)

	ret := C.INS_KPLGenP10ReqForSDK(c.ctx, C.int(sockFd), cdn, ckeyID, ckeyType, C.int(0), p10Data, &p10DataLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm2 generate p10 csr failed for %s, ret = %v", dn, ret)
	}
	csrBytes := C.GoBytes(unsafe.Pointer(p10Data), C.int(p10DataLen))
	return csrBytes, nil
}

func (c *ctx) iNS_KPLImportCert(sockFd int32, KeyID string, cert []byte) error {
	ckeyID := C.CString(KeyID)
	defer C.free(unsafe.Pointer(ckeyID))

	ret := C.INS_KPLImportCertForSDK(c.ctx, C.int(sockFd), ckeyID, cMessage(cert), C.uint(len(cert)))
	if ret != 0 {
		return fmt.Errorf("sm2 import cert err %d", ret)
	}
	return nil
}

func (c *ctx) signWithServer(sockFd int32, dn string, raw []byte) ([]byte, error) {
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))
	shaFunc := "SM3"
	cshaFunc := C.CString(shaFunc)
	defer C.free(unsafe.Pointer(cshaFunc))
	sig := C.NewUcharForXinanForSDK(72)
	sigLen := C.int(72)
	defer C.free(unsafe.Pointer(sig))

	ret := C.INS_RawSignDataForSDK(c.ctx, C.int(sockFd), cMessage(raw), C.int(len(raw)), cdn, cshaFunc, C.int(0), sig, &sigLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm2 sign failed, ret = %v", ret)
	}
	return C.GoBytes(unsafe.Pointer(sig), sigLen), nil
}

func (c *ctx) verifyWithServer(sockFd int32, dn string, raw, signRes []byte) bool {
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))
	shaFunc := "SM3"
	cshaFunc := C.CString(shaFunc)
	defer C.free(unsafe.Pointer(cshaFunc))

	ret := C.INS_RawVerifyDataForSDK(c.ctx, C.int(sockFd), cMessage(raw), C.int(len(raw)), cdn, cshaFunc, C.int(0), cMessage(signRes), C.int(len(signRes)))
	if ret != 0 {
		logger.Errorf("VerifyWithServer failed, ret = %d", ret)
		return false
	}
	return true
}

func (c *ctx) verifyWithCertServer(sockFd int32, cert, raw, signRes []byte) bool {
	shaFunc := "SM3"
	cshaFunc := C.CString(shaFunc)
	defer C.free(unsafe.Pointer(cshaFunc))

	ret := C.INS_RawVerifyWithCertForSDK(c.ctx, C.int(sockFd), cMessage(raw), C.int(len(raw)),
		cMessage(cert), C.int(len(cert)), cshaFunc, C.int(0),
		cMessage(signRes), C.int(len(signRes)))
	if ret != 0 {
		logger.Errorf("VerifyWithServer failed, ret = %d", ret)
		return false
	}
	return true
}
func (c *ctx) sm2Encrypt(sockFd int32, dn string, plaintext []byte) ([]byte, error) {
	ciphertext := C.NewUcharForXinanForSDK(C.int(len(plaintext) + 150))
	defer C.free(unsafe.Pointer(ciphertext))
	ciperLen := C.int(len(plaintext) + 150)
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))
	ret := C.INS_RawEncryptForSDK(c.ctx, C.int(sockFd), cMessage(plaintext), C.int(len(plaintext)), cdn, C.int(0), ciphertext, &ciperLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm2 encrypt err,ret = %d", ret)
	}
	return C.GoBytes(unsafe.Pointer(ciphertext), ciperLen), nil
}

func (c *ctx) sm2EncryptWithCert(sockFd int32, cert, plaintext []byte) ([]byte, error) {
	ciphertext := C.NewUcharForXinanForSDK(C.int(len(plaintext) + 150))
	defer C.free(unsafe.Pointer(ciphertext))
	ciperLen := C.int(len(plaintext) + 150)
	ret := C.INS_RawEncryptWithCertForSDK(c.ctx, C.int(sockFd), cMessage(plaintext), C.int(len(plaintext)),
		cMessage(cert), C.int(len(cert)), C.int(0), ciphertext, &ciperLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm2 encrypt err,ret = %d", ret)
	}
	return C.GoBytes(unsafe.Pointer(ciphertext), ciperLen), nil
}

func (c *ctx) sm2Decrypt(sockFd int32, dn string, ciphertext []byte) ([]byte, error) {
	plaintext := C.NewUcharForXinanForSDK(C.int(len(ciphertext)))
	defer C.free(unsafe.Pointer(plaintext))
	plainLen := C.int(len(ciphertext))
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))

	ret := C.INS_RawDecryptForSDK(c.ctx, C.int(sockFd), cMessage(ciphertext), C.int(len(ciphertext)), cdn, C.int(0), plaintext, &plainLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm2 decrypt err,ret = %d", ret)
	}
	return C.GoBytes(unsafe.Pointer(plaintext), plainLen), nil
}

func (c *ctx) sm3Hash(msg []byte) ([]byte, error) {
	shaFunc := "SM3"
	cshaFunc := C.CString(shaFunc)
	defer C.free(unsafe.Pointer(cshaFunc))
	retHash := make([]byte, 32)
	retLen := C.int(len(retHash))
	ret := C.INS_HashDataForSDK(c.ctx, C.int(-1), cshaFunc,
		cMessage(msg), (C.int)(len(msg)),
		(*C.uchar)(unsafe.Pointer(&retHash[0])), &retLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm3 hash err,ret is %d", ret)
	}
	return retHash[:retLen], nil
}

// 生成随机数作为对称密钥
func (c *ctx) generateSessionKey(sockFd int32) ([]byte, error) {
	keyLen := C.int(SM4_LEN)
	key := C.NewUcharForXinanForSDK(keyLen)
	defer C.free(unsafe.Pointer(key))
	// 生成随机数作为sm4的key
	ret := C.INS_GenRandomForSDK(c.ctx, C.int(sockFd), key, keyLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm4 hsmserver genRandom error ,ret is %d", ret)
	}
	return C.GoBytes(unsafe.Pointer(key), keyLen), nil
}

// sm4加密
func (c *ctx) sm4Encrypt(sockFd int32, key, src []byte, isKeyID bool) ([]byte, error) {
	var param C.SymmEncryptParam
	CivLen := C.int(SM4_LEN)
	iv := C.NewUcharForXinanForSDK(CivLen)
	defer C.free(unsafe.Pointer(iv))
	ret := C.INS_GenRandomForSDK(c.ctx, C.int(sockFd), iv, CivLen)
	if ret != 0 {
		return nil, fmt.Errorf("sm4 hsmserver genRandom error ,ret is %d", ret)
	}

	C.generateSymmForSDK(&param, iv)
	dst := C.NewUcharForXinanForSDK(C.int(SM4_LEN + len(src)))
	defer C.free(unsafe.Pointer(dst))
	dstLen := (C.int)(SM4_LEN + len(src))
	if isKeyID {
		ckey := C.CString(string(key))
		defer C.free(unsafe.Pointer(ckey))
		ret = C.INS_EncryptWithKeyIDForSDK(c.ctx, C.int(sockFd), ckey, &param,
			cMessage(src), C.int(len(src)), dst, &dstLen)
	} else {
		ret = C.INS_EncryptWithKeyForSDK(c.ctx, C.int(sockFd), cMessage(key), C.int(len(key)), &param,
			cMessage(src), C.int(len(src)), dst, &dstLen)
	}

	if ret != 0 {
		return []byte{}, fmt.Errorf("xin_an server is wrong ,ret is %d", ret)
	}

	out := make([]byte, 0)
	GoIv := []byte(C.GoBytes(unsafe.Pointer(iv), C.int(CivLen)))
	godst := C.GoBytes(unsafe.Pointer(dst), dstLen)

	out = append(GoIv, godst...)
	return out, nil
}

// sm4 解密
func (c *ctx) sm4Decrypt(sockFd int32, key, ciphertext []byte, isKeyID bool) ([]byte, error) {
	if len(ciphertext) < SM4_LEN {
		return nil, fmt.Errorf("ciphertext len too small")
	}
	iv := ciphertext[:SM4_LEN]
	ciphertext = ciphertext[SM4_LEN:]
	dst := C.NewUcharForXinanForSDK(C.int(len(ciphertext)))
	dstLen := (C.int)(len(ciphertext))
	var param C.SymmEncryptParam
	C.generateSymmForSDK(&param, (*C.uchar)(unsafe.Pointer(&iv[0])))
	var ret C.int
	if isKeyID {
		ckey := C.CString(string(key))
		defer C.free(unsafe.Pointer(ckey))
		ret = C.INS_DecryptWithKeyIDForSDK(c.ctx, C.int(sockFd), ckey,
			&param, cMessage(ciphertext), C.int(len(ciphertext)), dst, &dstLen)
	} else {
		ret = C.INS_DecryptWithKeyForSDK(c.ctx, C.int(sockFd), cMessage(key), C.int(len(key)),
			&param, cMessage(ciphertext), C.int(len(ciphertext)), dst, &dstLen)
	}

	if ret != 0 {
		return []byte{}, fmt.Errorf("xin_an server is wrong,ret is %d", ret)
	}
	return C.GoBytes(unsafe.Pointer(dst), dstLen), nil
}
