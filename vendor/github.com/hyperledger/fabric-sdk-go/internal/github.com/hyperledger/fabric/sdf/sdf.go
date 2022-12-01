package sdf

/*
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl
#cgo openbsd LDFLAGS: -ldl
#cgo freebsd LDFLAGS: -ldl

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sdf.h>
#include <stdint.h>

PDevice NewDeviceForSDK(){
	return (PDevice)malloc(sizeof(DEVICEINFO));
}
PUchar NewUcharForSDK(int l){
	return (PUchar)malloc(sizeof(unsigned char)*l);
}

PRSArefPublicKey NewRSAPublicKeyForSDK(){
	return (PRSArefPublicKey)malloc(sizeof(RSArefPublicKey));
}
PRSArefPublicKey ToRSAPublicKeyForSDK(unsigned int bits,void* m, void * e){
	PRSArefPublicKey p;
	p = NewRSAPublicKeyForSDK();
	p->bits = bits;
	memcpy(&(p->m[0]),m,RSAref_MAX_LEN);
	memcpy(&(p->e[0]),e,RSAref_MAX_LEN);
	return p;
}

PRSArefPrivateKey NewRSAPrivateKeyForSDK(){
	return (PRSArefPrivateKey)malloc(sizeof(RSArefPrivateKey));
}
PRSArefPrivateKey ToRSAPrivateKeyForSDK(unsigned int bits,void* m,void* e,void* d,void *prime1,
	void* prime2,void* pexp1,void* pexp2,void* coef){
	PRSArefPrivateKey p;
	p = NewRSAPrivateKeyForSDK();
	p->bits = bits;
	memcpy(&(p->m[0]),m,RSAref_MAX_LEN);
	memcpy(&(p->e[0]),e,RSAref_MAX_LEN);
	memcpy(&(p->d[0]),d,RSAref_MAX_LEN);
	memcpy(&(p->prime[0][0]),prime1,RSAref_MAX_LEN);
	memcpy(&(p->prime[1][0]),prime2,RSAref_MAX_LEN);
	memcpy(&(p->pexp[0][0]),pexp1,RSAref_MAX_LEN);
	memcpy(&(p->pexp[1][0]),pexp2,RSAref_MAX_LEN);
	memcpy(&(p->coef[0]),coef,RSAref_MAX_LEN);
	return p;
}
PECCrefPublicKey NewECCPublicKeyForSDK(){
	return (PECCrefPublicKey)malloc(sizeof(ECCrefPublicKey));
}
PECCrefPublicKey NewNullECCPublicKeyForSDK(){
	PECCrefPublicKey p;
	p = NULL;
	return p;
}
PECCrefPublicKey ToECCPublicKeyForSDK(unsigned int bits,void* x, void* y){
	PECCrefPublicKey p;
	p = NewECCPublicKeyForSDK();
	p->bits = bits;
	memcpy(&(p->x[0]),x,ECCref_MAX_LEN);
	memcpy(&(p->y[0]),y,ECCref_MAX_LEN);
	return p;
}

PECCrefPrivateKey NewECCPrivateKeyForSDK(){
	return (PECCrefPrivateKey)malloc(sizeof(ECCrefPrivateKey));
}
PECCrefPrivateKey ToECCPrivateKeyForSDK(unsigned int bits,void* d){
	PECCrefPrivateKey p;
	p = NewECCPrivateKeyForSDK();
	p->bits = bits;
	memcpy(&(p->D[0]),d,ECCref_MAX_LEN);
	return p;
}
PECCrefPrivateKey NewNullECCPrivateKeyForSDK(){
	PECCrefPrivateKey p;
	p = NULL;
	return p;
}

PUint NewUintForSDK(){
	return (PUint)malloc(sizeof(unsigned int));
}
PUint ToUintForSDK(unsigned int n){
	PUint p;
	p = NewUintForSDK();
    *p = n;
	return p;
}

PECCCipher NewECCCipherForSDK(){
	return (PECCCipher)malloc(sizeof(ECCCipher));
}
PECCCipher ToECCCipherForSDK(void* x,void *y, void *m ,unsigned int l,void *c){
	PECCCipher p;
	p = NewECCCipherForSDK();
	memcpy(&(p->x[0]),x,ECCref_MAX_LEN);
	memcpy(&(p->y[0]),y,ECCref_MAX_LEN);
	memcpy(&(p->M[0]),m,32);
	p->L = l;
	memcpy(&(p->C[0]),c,ECC_CIPHER_MAX);
	return p;
}

PECCSignature NewECCSignatureForSDK(){
	return (PECCSignature)malloc(sizeof(ECCSignature));
}
PECCSignature ToECCSignatureForSDK(void* r, void* s){
	PECCSignature p;
	p = NewECCSignatureForSDK();
	memcpy(&(p->r[0]),r,ECCref_MAX_LEN);
	memcpy(&(p->s[0]),s,ECCref_MAX_LEN);
	return p;
}

// New initializes a ctx and fills the symbol table.
struct sdfctx *NewSDFForSDK(const char *module)
{
	struct sdfctx *c = calloc(1, sizeof(struct sdfctx));
	c->handle = dlopen(module, RTLD_LAZY);
	if (c->handle == NULL) {
		free(c);
		return NULL;
	}
	c->api = (sdfAPI*)calloc(1, sizeof(sdfAPI));
	return c;
}

// 接口函数
int YX_SDF_OpenDeviceForSDK(struct sdfctx * c){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->openDevice == NULL){
		c->api->openDevice = (int (*)(void **))dlsym(c->handle,"SDF_OpenDevice");
	}
	if(c->api->openDevice == NULL){
		return NO_API_ERROR;
	}
	return c->api->openDevice(&(c->deviceHandle));
}

int YX_SDF_CloseDeviceForSDK(struct sdfctx * c){
	if(c == NULL || c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->closeDevice == NULL){
		c->api->closeDevice = (int (*)(void *))dlsym(c->handle,"SDF_CloseDevice");
	}
	if(c->api->closeDevice == NULL){
		return NO_API_ERROR;
	}
	return c->api->closeDevice(c->deviceHandle);
}

int YX_SDF_OpenSessionForSDK(struct sdfctx * c,void ** hSessionHandle){
	if(c == NULL || c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->openSession == NULL){
		c->api->openSession = (int (*)(void *,void **))dlsym(c->handle,"SDF_OpenSession");
	}
	if(c->api->openSession == NULL){
		return NO_API_ERROR;
	}
	return c->api->openSession(c->deviceHandle,hSessionHandle);
}

int YX_SDF_CloseSessionForSDK(struct sdfctx * c,uintptr_t hSessionHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->closeSession == NULL){
		c->api->closeSession = (int (*)(void *))dlsym(c->handle,"SDF_CloseSession");
	}
	if(c->api->closeSession == NULL){
		return NO_API_ERROR;
	}
	return c->api->closeSession((void*)hSessionHandle);
}

int YX_SDF_GetDeviceInfoForSDK (struct sdfctx *c, uintptr_t hSessionHandle,DEVICEINFO *pstDeviceInfo){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->getDeviceInfo == NULL){
		c->api->getDeviceInfo = (int (*)(void * ,DEVICEINFO *))dlsym(c->handle,"SDF_GetDeviceInfo");
	}
	if(c->api->getDeviceInfo == NULL){
		return NO_API_ERROR;
	}
	return c->api->getDeviceInfo((void*)hSessionHandle, pstDeviceInfo);
}

int YX_SDF_GenerateRandomForSDK(struct sdfctx *c, uintptr_t hSessionHandle,unsigned int uiLength, unsigned char *pucRandom){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateRandom == NULL){
		c->api->generateRandom = (int (*)(void *,unsigned int, unsigned char *))dlsym(c->handle,"SDF_GenerateRandom");
	}
	if(c->api->generateRandom == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateRandom((void*)hSessionHandle,uiLength,pucRandom);
}

int YX_SDF_GetPrivateKeyAccessRightForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiKeyType,unsigned int uiKeyIndex,
	unsigned char *pucPassword,unsigned int uiPwdLength ){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->getPrivateKeyAccessRight == NULL){
		c->api->getPrivateKeyAccessRight = (int (*)(void *,unsigned int,unsigned int, unsigned char *,unsigned int))dlsym(c->handle,"SDF_GetPrivateKeyAccessRight");
	}
	if(c->api->getPrivateKeyAccessRight == NULL){
		return NO_API_ERROR;
	}
	return c->api->getPrivateKeyAccessRight((void*)hSessionHandle, uiKeyType, uiKeyIndex, pucPassword, uiPwdLength);
}

int YX_SDF_ReleasePrivateKeyAccessRightForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiKeyType,unsigned int uiKeyIndex){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->releasePrivateKeyAccessRight == NULL){
		c->api->releasePrivateKeyAccessRight = (int (*)(void *,unsigned int, unsigned int))dlsym(c->handle,"SDF_ReleasePrivateKeyAccessRight");
	}
	if(c->api->releasePrivateKeyAccessRight == NULL){
		return NO_API_ERROR;
	}
	return  c->api->releasePrivateKeyAccessRight((void*)hSessionHandle, uiKeyType, uiKeyIndex);
}

int YX_SDF_ExportSignPublicKey_RSAForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiKeyIndex,RSArefPublicKey *pucPublicKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->exportSignPublicKeyRSA == NULL){
		c->api->exportSignPublicKeyRSA = (int (*)(void *,unsigned int, RSArefPublicKey *))dlsym(c->handle,"SDF_ExportSignPublicKey_RSA");
	}
	if(c->api->exportSignPublicKeyRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->exportSignPublicKeyRSA((void*)hSessionHandle, uiKeyIndex, pucPublicKey);
}

int YX_SDF_ExportEncPublicKey_RSAForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiKeyIndex,RSArefPublicKey *pucPublicKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->exportEncPublicKeyRSA == NULL){
		c->api->exportEncPublicKeyRSA = (int (*)(void *,unsigned int, RSArefPublicKey *))dlsym(c->handle,"SDF_ExportEncPublicKey_RSA");
	}
	if(c->api->exportEncPublicKeyRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->exportEncPublicKeyRSA((void*)hSessionHandle, uiKeyIndex, pucPublicKey);
}

int YX_SDF_GenerateKeyPair_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle,unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyPairRSA == NULL){
		c->api->generateKeyPairRSA = (int (*)(void *,unsigned int, RSArefPublicKey *,RSArefPrivateKey *))dlsym(c->handle,"SDF_GenerateKeyPair_RSA");
	}
	if(c->api->generateKeyPairRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyPairRSA((void*)hSessionHandle, uiKeyBits, pucPublicKey,pucPrivateKey);
}

int YX_SDF_GenerateKeyWithIPK_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle,unsigned int uiIPKIndex, unsigned int uiKeyBits,
								unsigned char * pucPublicKey, unsigned int * puiKeyLength, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyWithIPKRSA == NULL){
		c->api->generateKeyWithIPKRSA = (int (*)(void *,unsigned int, unsigned int, unsigned char *, unsigned int *, void **))dlsym(c->handle,"SDF_GenerateKeyWithIPK_RSA");
	}
	if(c->api->generateKeyWithIPKRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyWithIPKRSA((void*)hSessionHandle, uiIPKIndex, uiKeyBits, pucPublicKey, puiKeyLength, phKeyHandle);
}

int YX_SDF_GenerateKeyWithEPK_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
								unsigned char * pucKey, unsigned int * puiKeyLength, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyWithEPKRSA == NULL){
		c->api->generateKeyWithEPKRSA = (int (*)(void *,unsigned int, RSArefPublicKey *, unsigned char *, unsigned int *, void **))dlsym(c->handle,"SDF_GenerateKeyWithEPK_RSA");
	}
	if(c->api->generateKeyWithEPKRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyWithEPKRSA((void*)hSessionHandle, uiKeyBits, pucPublicKey, pucKey, puiKeyLength, phKeyHandle);
}

int YX_SDF_ImportKeyWithISK_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiISKIndex,
								unsigned char * pucPublicKey, unsigned int uiKeyLength, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->importKeyWithISKRSA == NULL){
		c->api->importKeyWithISKRSA = (int (*)(void *,unsigned int, unsigned char *, unsigned int, void **))dlsym(c->handle,"SDF_ImportKeyWithISK_RSA");
	}
	if(c->api->importKeyWithISKRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->importKeyWithISKRSA((void*)hSessionHandle, uiISKIndex, pucPublicKey, uiKeyLength, phKeyHandle);
}

int YX_SDF_ImportKeyForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucPublicKey, unsigned int uiKeyLength, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->importKey == NULL){
		c->api->importKey = (int (*)(void *,unsigned char *, unsigned int, void **))dlsym(c->handle,"SDF_ImportKey");
	}
	if(c->api->importKey == NULL){
		return NO_API_ERROR;
	}
	return c->api->importKey((void*)hSessionHandle, pucPublicKey, uiKeyLength, phKeyHandle);
}

int YX_SDF_ExchangeDigitEnvelopeBaseOnRSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey,
							unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *pucDELength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->exchangeDigitEnvelopeBaseOnRSA == NULL){
		c->api->exchangeDigitEnvelopeBaseOnRSA = (int (*)(void *,unsigned int, RSArefPublicKey *, unsigned char *, unsigned int,
				unsigned char *, unsigned int *))dlsym(c->handle,"SDF_ExchangeDigitEnvelopeBaseOnRSA");
	}
	if(c->api->exchangeDigitEnvelopeBaseOnRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->exchangeDigitEnvelopeBaseOnRSA((void*)hSessionHandle, uiKeyIndex, pucPublicKey, pucDEInput, uiDELength, pucDEOutput, pucDELength);
}

int YX_SDF_ExportSignPublicKey_ECCForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->exportSignPublicKeyECC == NULL){
		c->api->exportSignPublicKeyECC = (int (*)(void *,unsigned int, ECCrefPublicKey *))dlsym(c->handle,"SDF_ExportSignPublicKey_ECC");
	}
	if(c->api->exportSignPublicKeyECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->exportSignPublicKeyECC((void*)hSessionHandle, uiKeyIndex, pucPublicKey);
}

int YX_SDF_ExportEncPublicKey_ECCForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->exportEncPublicKeyECC == NULL){
		c->api->exportEncPublicKeyECC = (int (*)(void *,unsigned int, ECCrefPublicKey *))dlsym(c->handle,"SDF_ExportEncPublicKey_ECC");
	}
	if(c->api->exportEncPublicKeyECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->exportEncPublicKeyECC((void*)hSessionHandle, uiKeyIndex, pucPublicKey);
}

int YX_SDF_GenerateKeyPair_ECCForSDK(struct sdfctx * c,uintptr_t hSessionHandle,unsigned int uiAlgID, unsigned int uiKeyBits,
	ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyPairECC == NULL){
		c->api->generateKeyPairECC = (int (*)(void *,unsigned int,unsigned int, ECCrefPublicKey *, ECCrefPrivateKey *))dlsym(c->handle,"SDF_GenerateKeyPair_ECC");
	}
	if(c->api->generateKeyPairECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyPairECC((void*)hSessionHandle, uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
}

int YX_SDF_GenerateKeyWithIPK_ECCForSDK(struct sdfctx * c,uintptr_t hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
	ECCCipher *pucKey, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyWithIPKECC == NULL){
		c->api->generateKeyWithIPKECC = (int (*)(void *,unsigned int,unsigned int, ECCCipher *, void **))dlsym(c->handle,"SDF_GenerateKeyWithIPK_ECC");
	}
	if(c->api->generateKeyWithIPKECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyWithIPKECC((void*)hSessionHandle, uiIPKIndex, uiKeyBits, pucKey, phKeyHandle);
}

int YX_SDF_GenerateKeyWithEPK_ECCForSDK(struct sdfctx * c,uintptr_t hSessionHandle, unsigned int uiKeyBits,unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyWithEPKECC == NULL){
		c->api->generateKeyWithEPKECC = (int (*)(void *,unsigned int,unsigned int,ECCrefPublicKey*, ECCCipher *, void **))dlsym(c->handle,"SDF_GenerateKeyWithEPK_ECC");
	}
	if(c->api->generateKeyWithEPKECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyWithEPKECC((void*)hSessionHandle,uiKeyBits,uiAlgID, pucPublicKey, pucKey, phKeyHandle);
}
int YX_SDF_ImportKeyWithISK_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->importKeyWithISKECC == NULL){
		c->api->importKeyWithISKECC = (int (*)(void *,unsigned int,ECCCipher *, void **))dlsym(c->handle,"SDF_ImportKeyWithISK_ECC");
	}
	if(c->api->importKeyWithISKECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->importKeyWithISKECC((void*)hSessionHandle, uiISKIndex, pucKey, phKeyHandle);
}

int YX_SDF_ExchangeDigitEnvelopeBaseOnECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
				ECCrefPublicKey *pucPublicKey, ECCCipher * pucEncDataIn, ECCCipher *pucEncDataOut){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->exchangeDigitEnvelopeBaseOnECC == NULL){
		c->api->exchangeDigitEnvelopeBaseOnECC = (int (*)(void *,unsigned int,unsigned int, ECCrefPublicKey *,
				ECCCipher *, ECCCipher *))dlsym(c->handle,"SDF_ExchangeDigitEnvelopeBaseOnECC");
	}
	if(c->api->exchangeDigitEnvelopeBaseOnECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->exchangeDigitEnvelopeBaseOnECC((void*)hSessionHandle, uiKeyIndex, uiAlgID, pucPublicKey, pucEncDataIn, pucEncDataOut);
}

int YX_SDF_GenerateAgreementDataWithECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,
			unsigned int uiSponsorIDLength, ECCrefPublicKey * pucSponsorPublicKey, ECCrefPublicKey * pucSponsorTmpPublicKey, void ** phAgreementHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateAgreementDataWithECC == NULL){
		c->api->generateAgreementDataWithECC = (int (*)(void *,unsigned int,unsigned int,unsigned char *, unsigned int,
				ECCrefPublicKey *,ECCrefPublicKey *, void **))dlsym(c->handle,"SDF_GenerateAgreementDataWithECC");
	}
	if(c->api->generateAgreementDataWithECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateAgreementDataWithECC((void*)hSessionHandle, uiISKIndex, uiKeyBits, pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey, phAgreementHandle);
}

int YX_SDF_GenerateKeyWithECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle,unsigned char *pucResponseID, unsigned int uiResponseIDLength,
		ECCrefPublicKey * pucResponsePublicKey, ECCrefPublicKey * pucResponseTmpPublicKey, uintptr_t phAgreementHandle, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyWithECC == NULL){
		c->api->generateKeyWithECC = (int (*)(void *,unsigned char *, unsigned int,ECCrefPublicKey *,
			ECCrefPublicKey *, void *,void **))dlsym(c->handle,"SDF_GenerateKeyWithECC");
	}
	if(c->api->generateKeyWithECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyWithECC((void*)hSessionHandle, pucResponseID, uiResponseIDLength, pucResponsePublicKey, pucResponseTmpPublicKey, (void*)phAgreementHandle, phKeyHandle);
}

int YX_SDF_GenerateAgreementDataAndKeyWithECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
			unsigned char *pucResponseID, unsigned int uiResponseIDLength, unsigned char *pucSponsorID,unsigned int uiSponsorIDLength,
			ECCrefPublicKey * pucSponsorPublicKey, ECCrefPublicKey * pucSponsorTmpPublicKey,
			ECCrefPublicKey * pucResponsePublicKey, ECCrefPublicKey * pucResponseTmpPublicKey, void ** phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateAgreementDataAndKeyWithECC == NULL){
		c->api->generateAgreementDataAndKeyWithECC = (int (*)(void *,unsigned int,unsigned int,unsigned char *, unsigned int, unsigned char *, unsigned int,
				ECCrefPublicKey *,ECCrefPublicKey *, ECCrefPublicKey *,ECCrefPublicKey *, void **))dlsym(c->handle,"SDF_GenerateAgreementDataAndKeyWithECC");
	}
	if(c->api->generateAgreementDataAndKeyWithECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateAgreementDataAndKeyWithECC((void*)hSessionHandle, uiISKIndex, uiKeyBits,pucResponseID, uiResponseIDLength,
		pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey, pucResponsePublicKey, pucResponseTmpPublicKey, phKeyHandle);
}

int YX_SDF_GenerateKeyWithKEKForSDK(struct sdfctx * c, uintptr_t hSessionHandle,unsigned int uiKeyBits, unsigned int uiAlgID,
		unsigned int  uiKEKIndex, unsigned char * pucKey,unsigned int *puiKeyLength, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->generateKeyWithKEK == NULL){
		c->api->generateKeyWithKEK = (int (*)(void *,unsigned int, unsigned int,unsigned int, unsigned char *,
			unsigned int *, void **))dlsym(c->handle,"SDF_GenerateKeyWithKEK");
	}
	if(c->api->generateKeyWithKEK == NULL){
		return NO_API_ERROR;
	}
	return c->api->generateKeyWithKEK((void*)hSessionHandle, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
}

int YX_SDF_ImportKeyWithKEKForSDK(struct sdfctx * c, uintptr_t hSessionHandle,unsigned int uiAlgID, unsigned int  uiKEKIndex,
	unsigned char * pucKey,unsigned int uiKeyLength, void **phKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->importKeyWithKEK == NULL){
		c->api->importKeyWithKEK = (int (*)(void *,unsigned int, unsigned int, unsigned char *,
			unsigned int, void **))dlsym(c->handle,"SDF_ImportKeyWithKEK");
	}
	if(c->api->importKeyWithKEK == NULL){
		return NO_API_ERROR;
	}
	return c->api->importKeyWithKEK((void*)hSessionHandle, uiAlgID, uiKEKIndex, pucKey, uiKeyLength, phKeyHandle);
}

int YX_SDF_DestroyKeyForSDK(struct sdfctx * c, uintptr_t hSessionHandle, uintptr_t hKeyHandle){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->destroyKey == NULL){
		c->api->destroyKey = (int (*)(void *, void *))dlsym(c->handle,"SDF_DestroyKey");
	}
	if(c->api->destroyKey == NULL){
		return NO_API_ERROR;
	}
	return c->api->destroyKey((void*)hSessionHandle, (void*)hKeyHandle);
}

int YX_SDF_ExternalPublicKeyOperation_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, RSArefPublicKey *pucPublicKey,unsigned char * pucDataInput,
					unsigned int uiInputLength, unsigned char * pucDataOutput, unsigned int *puiOutputLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->externalPublicKeyOperationRSA == NULL){
		c->api->externalPublicKeyOperationRSA = (int (*)(void *, RSArefPublicKey *, unsigned char *, unsigned int,
			unsigned char *, unsigned int *))dlsym(c->handle,"SDF_ExternalPublicKeyOperation_RSA");
	}
	if(c->api->externalPublicKeyOperationRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->externalPublicKeyOperationRSA((void*)hSessionHandle, pucPublicKey, pucDataInput,uiInputLength, pucDataOutput, puiOutputLength);
}

int YX_SDF_InternalPublicKeyOperation_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiKeyIndex,unsigned char * pucDataInput,
					unsigned int uiInputLength, unsigned char * pucDataOutput, unsigned int *puiOutputLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->internalPublicKeyOperationRSA == NULL){
		c->api->internalPublicKeyOperationRSA = (int (*)(void *, unsigned int, unsigned char *, unsigned int,
			unsigned char *, unsigned int *))dlsym(c->handle,"SDF_InternalPublicKeyOperation_RSA");
	}
	if(c->api->internalPublicKeyOperationRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->internalPublicKeyOperationRSA((void*)hSessionHandle, uiKeyIndex, pucDataInput,uiInputLength, pucDataOutput, puiOutputLength);
}

int YX_SDF_InternalPrivateKeyOperation_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiKeyIndex,unsigned char * pucDataInput,
					unsigned int uiInputLength, unsigned char * pucDataOutput, unsigned int *puiOutputLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->internalPrivateKeyOperationRSA == NULL){
		c->api->internalPrivateKeyOperationRSA = (int (*)(void *, unsigned int, unsigned char *, unsigned int,
			unsigned char *, unsigned int *))dlsym(c->handle,"SDF_InternalPrivateKeyOperation_RSA");
	}
	if(c->api->internalPrivateKeyOperationRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->internalPrivateKeyOperationRSA((void*)hSessionHandle, uiKeyIndex, pucDataInput,uiInputLength, pucDataOutput, puiOutputLength);
}

int YX_SDF_ExternalPrivateKeyOperation_RSAForSDK(struct sdfctx * c, uintptr_t hSessionHandle, RSArefPrivateKey *pucPrivateKey,unsigned char * pucDataInput,
					unsigned int uiInputLength, unsigned char * pucDataOutput, unsigned int *puiOutputLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->externalPrivateKeyOperationRSA == NULL){
		c->api->externalPrivateKeyOperationRSA = (int (*)(void *, RSArefPrivateKey *, unsigned char *, unsigned int,
			unsigned char *, unsigned int *))dlsym(c->handle,"SDF_ExternalPrivateKeyOperation_RSA");
	}
	if(c->api->externalPrivateKeyOperationRSA == NULL){
		return NO_API_ERROR;
	}
	return c->api->externalPrivateKeyOperationRSA((void*)hSessionHandle, pucPrivateKey, pucDataInput,uiInputLength, pucDataOutput, puiOutputLength);
}

int YX_SDF_InternalSign_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiISKIndex,unsigned char * pucData,
					unsigned int uiDataLength, ECCSignature * pucSignature){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->internalSignECC == NULL){
		c->api->internalSignECC = (int (*)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature *))dlsym(c->handle,"SDF_InternalSign_ECC");
	}
	if(c->api->internalSignECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->internalSignECC((void*)hSessionHandle, uiISKIndex, pucData, uiDataLength, pucSignature);
}

int YX_SDF_ExternalSign_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle,unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char * pucData,
					unsigned int uiDataLength, ECCSignature * pucSignature){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	//江南天安接口不标准
	if(c->api->externalSignECC == NULL){
		c->api->externalSignECC = (int (*)(void *, unsigned int, ECCrefPrivateKey *, unsigned char *, unsigned int,
			ECCSignature *))dlsym(c->handle,"SDF_ExternalSign_ECC_Ex");
	}
	if(c->api->externalSignECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->externalSignECC((void*)hSessionHandle,uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
}

int YX_SDF_ExternalVerify_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
					unsigned char * pucData, unsigned int uiDataLength, ECCSignature * pucSignature){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->externalVerifyECC == NULL){
		c->api->externalVerifyECC = (int (*)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int, ECCSignature *))dlsym(c->handle,"SDF_ExternalVerify_ECC");
	}
	if(c->api->externalVerifyECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->externalVerifyECC((void*)hSessionHandle,uiAlgID, pucPublicKey, pucData, uiDataLength, pucSignature);
}

int YX_SDF_InternalVerify_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiISKIndex, unsigned char * pucData,
				unsigned int uiDataLength, ECCSignature * pucSignature){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->internalVerifyECC == NULL){
		c->api->internalVerifyECC = (int (*)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature *))dlsym(c->handle,"SDF_InternalVerify_ECC");
	}
	if(c->api->internalVerifyECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->internalVerifyECC((void*)hSessionHandle, uiISKIndex, pucData, uiDataLength, pucSignature);
}

int YX_SDF_ExternalEncrypt_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
					unsigned char * pucData, unsigned int uiDataLength, ECCCipher * pucEncData){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->externalEncryptECC == NULL){
		c->api->externalEncryptECC = (int (*)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int, ECCCipher *))dlsym(c->handle,"SDF_ExternalEncrypt_ECC");
	}
	if(c->api->externalEncryptECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->externalEncryptECC((void*)hSessionHandle,uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
}

int YX_SDF_ExternalDecrypt_ECCForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiAlgID, unsigned int uiISKIndex, ECCrefPrivateKey *pucPrivateKey,
					ECCCipher *pucEncData, unsigned char * pucData, unsigned int *puiDataLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	// 江南天安加密机这个接口不标准
	if(c->api->externalDecryptECC == NULL){
		c->api->externalDecryptECC = (int (*)(void *, unsigned int,unsigned int,  ECCrefPrivateKey *, ECCCipher *,
				unsigned char *, unsigned int *))dlsym(c->handle,"SDF_E_Decrypt_ECC");
	}
	if(c->api->externalDecryptECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->externalDecryptECC((void*)hSessionHandle,uiAlgID, uiISKIndex, pucPrivateKey, pucEncData, pucData, puiDataLength);
}

int YX_SDF_EncryptForSDK(struct sdfctx * c, uintptr_t hSessionHandle, uintptr_t hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
		unsigned char * pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->encrypt == NULL){
		c->api->encrypt = (int (*)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int,
		unsigned char*, unsigned int *))dlsym(c->handle,"SDF_Encrypt");
	}
	if(c->api->encrypt == NULL){
		return NO_API_ERROR;
	}
	return c->api->encrypt((void*)hSessionHandle,(void*)hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, puiEncDataLength);
}

int YX_SDF_DecryptForSDK(struct sdfctx * c, uintptr_t hSessionHandle, uintptr_t hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
		unsigned char * pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->decrypt == NULL){
		c->api->decrypt = (int (*)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int,
		unsigned char*, unsigned int *))dlsym(c->handle,"SDF_Decrypt");
	}
	if(c->api->decrypt == NULL){
		return NO_API_ERROR;
	}
	return c->api->decrypt((void*)hSessionHandle,(void *)hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucData, puiDataLength);
}

int YX_SDF_CalculateMACForSDK(struct sdfctx * c, uintptr_t hSessionHandle, uintptr_t hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
		unsigned char * pucData, unsigned int uiDataLength, unsigned char *pucMAC, unsigned int *puiMACLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->calculateMAC == NULL){
		c->api->calculateMAC = (int (*)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int,
		unsigned char*, unsigned int *))dlsym(c->handle,"SDF_CalculateMAC");
	}
	if(c->api->calculateMAC == NULL){
		return NO_API_ERROR;
	}
	return c->api->calculateMAC((void*)hSessionHandle,(void*)hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC, puiMACLength);
}

int YX_SDF_HashInitForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
		unsigned char * pucID, unsigned int uiIDLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->hashInit == NULL){
		c->api->hashInit = (int (*)(void *,unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int))dlsym(c->handle,"SDF_HashInit");
	}
	if(c->api->hashInit == NULL){
		return NO_API_ERROR;
	}
	return c->api->hashInit((void*)hSessionHandle, uiAlgID, pucPublicKey, pucID, uiIDLength);
}

int YX_SDF_HashUpdateForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucData, unsigned int uiDataLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->hashUpdate == NULL){
		c->api->hashUpdate = (int (*)(void *, unsigned char *, unsigned int))dlsym(c->handle,"SDF_HashUpdate");
	}
	if(c->api->hashUpdate == NULL){
		return NO_API_ERROR;
	}
	return c->api->hashUpdate((void*)hSessionHandle, pucData, uiDataLength);
}

int YX_SDF_HashFinalForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucHash, unsigned int *puiHashLength){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->hashFinal == NULL){
		c->api->hashFinal = (int (*)(void *, unsigned char *, unsigned int *))dlsym(c->handle,"SDF_HashFinal");
	}
	if(c->api->hashFinal == NULL){
		return NO_API_ERROR;
	}
	return c->api->hashFinal((void*)hSessionHandle, pucHash, puiHashLength);
}

int YX_SDF_CreateFileForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucFileName, unsigned int uiNameLen, unsigned int uiFileSize){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->createFile == NULL){
		c->api->createFile = (int (*)(void *, unsigned char *, unsigned int, unsigned int))dlsym(c->handle,"SDF_CreateFile");
	}
	if(c->api->createFile == NULL){
		return NO_API_ERROR;
	}
	return c->api->createFile((void*)hSessionHandle, pucFileName, uiNameLen, uiFileSize);
}

int YX_SDF_ReadFileForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucFileName, unsigned int uiNameLen,
		unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->readFile == NULL){
		c->api->readFile = (int (*)(void *, unsigned char *, unsigned int, unsigned int,
			unsigned int *, unsigned char *))dlsym(c->handle,"SDF_ReadFile");
	}
	if(c->api->readFile == NULL){
		return NO_API_ERROR;
	}
	return c->api->readFile((void*)hSessionHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);
}

int YX_SDF_WriteFileForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucFileName, unsigned int uiNameLen,
		unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->writeFile == NULL){
		c->api->writeFile = (int (*)(void *, unsigned char *, unsigned int, unsigned int,
			unsigned int, unsigned char *))dlsym(c->handle,"SDF_WriteFile");
	}
	if(c->api->writeFile == NULL){
		return NO_API_ERROR;
	}
	return c->api->writeFile((void*)hSessionHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
}
int YX_SDF_DeleteFileForSDK(struct sdfctx * c, uintptr_t hSessionHandle, unsigned char * pucFileName, unsigned int uiNameLen){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->deleteFile == NULL){
		c->api->deleteFile = (int (*)(void *, unsigned char *, unsigned int))dlsym(c->handle,"SDF_DeleteFile");
	}
	if(c->api->deleteFile == NULL){
		return NO_API_ERROR;
	}
	return c->api->deleteFile((void*)hSessionHandle, pucFileName, uiNameLen);
}

int YX_SDF_GetIndexForSDK(struct sdfctx *c, uintptr_t hSessionHandle, unsigned int uiAlgID, char *pcKeyLabel, unsigned int *puiKeyIndex){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->getIndex == NULL){
		c->api->getIndex = (int (*)(void *, unsigned int, char *, unsigned int *))dlsym(c->handle,"SDF_E_GetIndex");
	}
	if(c->api->getIndex == NULL){
		return NO_API_ERROR;
	}
	return c->api->getIndex((void*)hSessionHandle, uiAlgID, pcKeyLabel, puiKeyIndex);

}

int YX_SDF_ImportKeyPair_ECCForSDK(struct sdfctx *c, uintptr_t hSessionHandle, unsigned int uiAlgID, unsigned int uiISKIndex,
		char *pcKeyLabel, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey){
	if(c == NULL ||  c->handle == NULL || c->api == NULL){
		return NO_HANDLE_ERROR;
	}
	if(c->api->importKeyPairECC == NULL){
		c->api->importKeyPairECC = (int (*)(void *, unsigned int, unsigned int, char *,
		ECCrefPublicKey *, ECCrefPrivateKey *))dlsym(c->handle,"SDF_E_ImportKeyPair_ECC");
	}
	if(c->api->importKeyPairECC == NULL){
		return NO_API_ERROR;
	}
	return c->api->importKeyPairECC((void*)hSessionHandle, uiAlgID, uiISKIndex, pcKeyLabel, pucPublicKey, pucPrivateKey);

}
*/
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

type Ctx struct {
	ctx *C.struct_sdfctx
}

func New(module string) *Ctx {
	c := new(Ctx)
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))
	c.ctx = C.NewSDFForSDK(mod)
	if c.ctx == nil {
		return nil
	}
	return c
}

func (ctx *Ctx) OpenDevice() error {
	rv := C.YX_SDF_OpenDeviceForSDK(ctx.ctx)
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) CloseDevice() error {
	rv := C.YX_SDF_CloseDeviceForSDK(ctx.ctx)
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) OpenSession() (uintptr, error) {
	var session unsafe.Pointer
	rv := Error(C.YX_SDF_OpenSessionForSDK(ctx.ctx, &session))
	if rv != SDR_OK {
		return uintptr(0), errors.New(Error(rv).Error())
	}
	return uintptr(session), nil
}

func (ctx *Ctx) CloseSession(session uintptr) error {
	rv := C.YX_SDF_CloseSessionForSDK(ctx.ctx, C.uintptr_t(session))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) GetDeviceInfo(session uintptr) (DeviceInfo, error) {
	d := C.NewDeviceForSDK()
	defer C.free(unsafe.Pointer(d))
	rv := C.YX_SDF_GetDeviceInfoForSDK(ctx.ctx, C.uintptr_t(session), d)
	var deviceInfo DeviceInfo
	if rv != SDR_OK {
		return deviceInfo, errors.New(Error(rv).Error())
	}
	deviceInfo = DeviceInfo{
		IssuerName:      strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&d.IssuerName[0]), 40)), " "),
		DeviceName:      strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&d.DeviceName[0]), 16)), " "),
		DeviceSerial:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&d.DeviceSerial[0]), 16)), " "),
		DeviceVersion:   uint(d.DeviceVersion),
		StandardVersion: uint(d.StandardVersion),
		AsymAlgAbility:  [2]uint{uint(d.AsymAlgAbility[0]), uint(d.AsymAlgAbility[1])},
		SymAlgAbility:   uint(d.SymAlgAbility),
		HashAlgAbility:  uint(d.HashAlgAbility),
		BufferSize:      uint(d.BufferSize),
		Dmkcv:           [2]uint{uint(d.Dmkcv[0]), uint(d.Dmkcv[1])},
	}
	return deviceInfo, nil
}

func (ctx *Ctx) GenerateRandom(session uintptr, length uint) ([]byte, error) {
	// 文档中要求缓冲区比传入的len大一些
	ret := C.NewUcharForSDK(C.int(length + 1))
	defer C.free(unsafe.Pointer(ret))
	rv := C.YX_SDF_GenerateRandomForSDK(ctx.ctx, C.uintptr_t(session), C.uint(length), ret)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(ret), C.int(length)), nil
}

func (ctx *Ctx) GetPrivateKeyAccessRight(session uintptr, keyType, keyIndex uint, password []byte) error {
	rv := C.YX_SDF_GetPrivateKeyAccessRightForSDK(ctx.ctx, C.uintptr_t(session), (C.uint)(keyType), (C.uint)(keyIndex), cMessage(password), (C.uint)(len(password)))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) ReleasePrivateKeyAccessRight(session uintptr, keyType, keyIndex uint) error {
	rv := C.YX_SDF_ReleasePrivateKeyAccessRightForSDK(ctx.ctx, C.uintptr_t(session), (C.uint)(keyType), C.uint(keyIndex))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) ExportSignPublicKeyRSA(session uintptr, keyIndex uint) (*RSAPublicKey, error) {
	pubKey := C.NewRSAPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	rv := C.YX_SDF_ExportSignPublicKey_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), pubKey)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return CRSAPublicKeyToGo(pubKey), nil
}

func (ctx *Ctx) ExportEncPublicKeyRSA(session uintptr, keyIndex uint) (*RSAPublicKey, error) {
	pubKey := C.NewRSAPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	rv := C.YX_SDF_ExportEncPublicKey_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), pubKey)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return CRSAPublicKeyToGo(pubKey), nil
}

func (ctx *Ctx) GenerateKeyPairRSA(session uintptr, bits uint) (*RSAPublicKey, *RSAPrivateKey, error) {
	pubKey := C.NewRSAPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	privKey := C.NewRSAPrivateKeyForSDK()
	defer C.free(unsafe.Pointer(privKey))
	rv := C.YX_SDF_GenerateKeyPair_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(bits), pubKey, privKey)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	return CRSAPublicKeyToGo(pubKey), CRSAPrivateKeyToGo(privKey), nil
}

func (ctx *Ctx) GenerateKeyWithIPKRSA(session uintptr, keyIndex, bits uint) ([]byte, uintptr, error) {
	pucKey := C.NewUcharForSDK(C.int(bits + 1))
	defer C.free(unsafe.Pointer(pucKey))
	pucKeyLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(pucKeyLen))
	var handle unsafe.Pointer
	rv := C.YX_SDF_GenerateKeyWithIPK_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), C.uint(bits), pucKey, pucKeyLen, &handle)
	if rv != SDR_OK {
		return nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(pucKey), C.int(*pucKeyLen)), uintptr(handle), nil
}

func (ctx *Ctx) GenerateKeyWithEPKRSA(session uintptr, bits uint, pub *RSAPublicKey) ([]byte, uintptr, error) {
	if pub == nil {
		return nil, uintptr(0), errors.New("pub key not be nil")
	}
	pucKey := C.NewUcharForSDK(C.int(bits + 1))
	defer C.free(unsafe.Pointer(pucKey))
	pucKeyLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(pucKeyLen))
	var handle unsafe.Pointer
	pubKey := C.ToRSAPublicKeyForSDK(C.uint(pub.Bits), unsafe.Pointer(&pub.M[0]), unsafe.Pointer(&pub.E[0]))
	defer C.free(unsafe.Pointer(pubKey))
	rv := C.YX_SDF_GenerateKeyWithEPK_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(bits), pubKey, pucKey, pucKeyLen, &handle)
	if rv != SDR_OK {
		return nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(pucKey), C.int(*pucKeyLen)), uintptr(handle), nil
}

func (ctx *Ctx) ImportKeyWithISKRSA(session uintptr, ISKIndex uint, pucKey []byte) (uintptr, error) {
	l := len(pucKey)
	var ret unsafe.Pointer
	rv := C.YX_SDF_ImportKeyWithISK_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(ISKIndex), cMessage(pucKey), C.uint(l), &ret)
	if rv != SDR_OK {
		return uintptr(0), errors.New(Error(rv).Error())
	}
	return uintptr(ret), nil
}

func (ctx *Ctx) ExchangeDigitEnvelopeBaseOnRSA(session uintptr, keyIndex uint, pucPubKey *RSAPublicKey, input []byte) ([]byte, error) {
	if pucPubKey == nil {
		return nil, errors.New("pub key not be nil")
	}
	output := C.NewUcharForSDK(C.int(2 * len(input)))
	defer C.free(unsafe.Pointer(output))
	outputLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(outputLen))
	pubKey := C.ToRSAPublicKeyForSDK(C.uint(pucPubKey.Bits), unsafe.Pointer(&pucPubKey.M[0]), unsafe.Pointer(&pucPubKey.E[0]))
	defer C.free(unsafe.Pointer(pubKey))
	rv := C.YX_SDF_ExchangeDigitEnvelopeBaseOnRSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), pubKey, cMessage(input), C.uint(len(input)), output, outputLen)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(output), C.int(*outputLen)), nil
}

func (ctx *Ctx) ExportSignPublicKeyECC(session uintptr, keyIndex uint) (*ECCPublicKey, error) {
	pubKey := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	rv := C.YX_SDF_ExportSignPublicKey_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), pubKey)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return CECCPublicKeyToGo(pubKey), nil
}

func (ctx *Ctx) ExportEncPublicKeyECC(session uintptr, keyIndex uint) (*ECCPublicKey, error) {
	pubKey := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	rv := C.YX_SDF_ExportEncPublicKey_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), pubKey)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return CECCPublicKeyToGo(pubKey), nil
}

func (ctx *Ctx) GenerateKeyPairECC(session uintptr, algID, bits uint) (*ECCPublicKey, *ECCPrivateKey, error) {
	pubKey := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	privKey := C.NewECCPrivateKeyForSDK()
	defer C.free(unsafe.Pointer(privKey))
	rv := C.YX_SDF_GenerateKeyPair_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algID), C.uint(bits), pubKey, privKey)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	return CECCPublicKeyToGo(pubKey), CECCPrivateKeyToGo(privKey), nil
}

func (ctx *Ctx) GenerateKeyWithIPKECC(session uintptr, keyIndex, bits uint) (*ECCCipher, uintptr, error) {
	pucKey := C.NewECCCipherForSDK()
	defer C.free(unsafe.Pointer(pucKey))
	var ret unsafe.Pointer
	rv := C.YX_SDF_GenerateKeyWithIPK_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), C.uint(bits), pucKey, &ret)
	if rv != SDR_OK {
		return nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return CECCCipherToGo(pucKey), uintptr(ret), nil
}

func (ctx *Ctx) GenerateKeyWithEPKECC(session uintptr, bits, algId uint, pubKey *ECCPublicKey) (*ECCCipher, uintptr, error) {
	if pubKey == nil {
		return nil, uintptr(0), errors.New("pub key not be nil")
	}
	pucKey := C.NewECCCipherForSDK()
	defer C.free(unsafe.Pointer(pucKey))
	var ret unsafe.Pointer

	pub := C.ToECCPublicKeyForSDK(C.uint(pubKey.Bits), unsafe.Pointer(&pubKey.X[0]), unsafe.Pointer(&pubKey.Y[0]))
	defer C.free(unsafe.Pointer(pub))
	rv := C.YX_SDF_GenerateKeyWithEPK_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(bits), C.uint(algId), pub, pucKey, &ret)
	if rv != SDR_OK {
		return nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return CECCCipherToGo(pucKey), uintptr(ret), nil
}

func (ctx *Ctx) ImportKeyWithISKECC(session uintptr, keyIndex uint, pucKey *ECCCipher) (uintptr, error) {
	if pucKey == nil {
		return uintptr(0), errors.New("pub key not be nil")
	}
	var ret unsafe.Pointer
	cpucKey := C.ToECCCipherForSDK(unsafe.Pointer(&pucKey.X[0]), unsafe.Pointer(&pucKey.Y[0]), unsafe.Pointer(&pucKey.M[0]), C.uint(pucKey.L), unsafe.Pointer(&pucKey.C[0]))
	defer C.free(unsafe.Pointer(cpucKey))
	rv := C.YX_SDF_ImportKeyWithISK_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), cpucKey, &ret)
	if rv != SDR_OK {
		return uintptr(0), errors.New(Error(rv).Error())
	}
	return uintptr(ret), nil
}

func (ctx *Ctx) ExchangeDigitEnvelopeBaseOnECC(session uintptr, keyIndex, algId uint, pubKey *ECCPublicKey, pucKey *ECCCipher) (*ECCCipher, error) {
	if pubKey == nil || pucKey == nil {
		return nil, errors.New("pub key and puckey not be nil")
	}
	pucData := C.NewECCCipherForSDK()
	defer C.free(unsafe.Pointer(pucData))
	pub := C.ToECCPublicKeyForSDK(C.uint(pubKey.Bits), unsafe.Pointer(&pubKey.X[0]), unsafe.Pointer(&pubKey.Y[0]))
	defer C.free(unsafe.Pointer(pub))
	cpucKey := C.ToECCCipherForSDK(unsafe.Pointer(&pucKey.X[0]), unsafe.Pointer(&pucKey.Y[0]), unsafe.Pointer(&pucKey.M[0]),
		C.uint(pucKey.L), unsafe.Pointer(&pucKey.C[0]))
	defer C.free(unsafe.Pointer(cpucKey))

	rv := C.YX_SDF_ExchangeDigitEnvelopeBaseOnECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), C.uint(algId), pub, cpucKey, pucData)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return CECCCipherToGo(pucData), nil
}

func (ctx *Ctx) GenerateAgreementDataWithECC(session uintptr, keyIndex, bits uint, sponsorId []byte) (*ECCPublicKey, *ECCPublicKey, uintptr, error) {
	var handle unsafe.Pointer
	pubKey := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(pubKey))
	tmpPub := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(tmpPub))

	rv := C.YX_SDF_GenerateAgreementDataWithECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(keyIndex), C.uint(bits),
		cMessage(sponsorId), C.uint(len(sponsorId)), pubKey, tmpPub, &handle)
	if rv != SDR_OK {
		return nil, nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return CECCPublicKeyToGo(pubKey), CECCPublicKeyToGo(tmpPub), uintptr(handle), nil
}

func (ctx *Ctx) GenerateKeyWithECC(session uintptr, responseId []byte, responsePubKey *ECCPublicKey,
	responseTmpPubKey *ECCPublicKey, agreementHandle uintptr) (uintptr, error) {
	if responsePubKey == nil || responseTmpPubKey == nil {
		return uintptr(0), errors.New("responsePubKey and responseTmpPubKey not be nil")
	}
	var kh unsafe.Pointer
	pub := C.ToECCPublicKeyForSDK(C.uint(responsePubKey.Bits), unsafe.Pointer(&responsePubKey.X[0]), unsafe.Pointer(&responsePubKey.Y[0]))
	defer C.free(unsafe.Pointer(pub))
	tmpPub := C.ToECCPublicKeyForSDK(C.uint(responseTmpPubKey.Bits), unsafe.Pointer(&responseTmpPubKey.X[0]), unsafe.Pointer(&responseTmpPubKey.Y[0]))
	defer C.free(unsafe.Pointer(tmpPub))
	rv := C.YX_SDF_GenerateKeyWithECCForSDK(ctx.ctx, C.uintptr_t(session), cMessage(responseId), C.uint(len(responseId)),
		pub, tmpPub, C.uintptr_t(agreementHandle), &kh)
	if rv != SDR_OK {
		return uintptr(0), errors.New(Error(rv).Error())
	}
	return uintptr(kh), nil
}

func (ctx *Ctx) GenerateAgreementDataAndKeyWithECC(session uintptr, uiISKindex, bits uint, responseId, sponsorId []byte,
	sponsorPubKey *ECCPublicKey, sponsorTmpPubKey *ECCPublicKey) (*ECCPublicKey, *ECCPublicKey, uintptr, error) {
	if sponsorPubKey == nil || sponsorTmpPubKey == nil {
		return nil, nil, uintptr(0), errors.New("sponsorPubKey and sponsorTmpPubKey not be nil")
	}
	var handle unsafe.Pointer
	responsePubKey := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(responsePubKey))
	responseTmpPubKey := C.NewECCPublicKeyForSDK()
	defer C.free(unsafe.Pointer(responseTmpPubKey))
	pub := C.ToECCPublicKeyForSDK(C.uint(sponsorPubKey.Bits), unsafe.Pointer(&sponsorPubKey.X[0]), unsafe.Pointer(&sponsorPubKey.Y[0]))
	defer C.free(unsafe.Pointer(pub))
	tmpPub := C.ToECCPublicKeyForSDK(C.uint(sponsorTmpPubKey.Bits), unsafe.Pointer(&sponsorTmpPubKey.X[0]), unsafe.Pointer(&sponsorTmpPubKey.Y[0]))
	defer C.free(unsafe.Pointer(tmpPub))

	rv := C.YX_SDF_GenerateAgreementDataAndKeyWithECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(uiISKindex), C.uint(bits),
		cMessage(responseId), C.uint(len(responseId)),
		cMessage(sponsorId), C.uint(len(sponsorId)),
		pub, tmpPub, responsePubKey, responseTmpPubKey, &handle)
	if rv != SDR_OK {
		return nil, nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return CECCPublicKeyToGo(responsePubKey), CECCPublicKeyToGo(responseTmpPubKey), uintptr(handle), nil
}

func (ctx *Ctx) GenerateKeyWithKEK(session uintptr, bits, algId, index uint) ([]byte, uintptr, error) {
	data := C.NewUcharForSDK(C.int(bits + 1))
	defer C.free(unsafe.Pointer(data))
	l := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(l))
	var handle unsafe.Pointer
	rv := C.YX_SDF_GenerateKeyWithKEKForSDK(ctx.ctx, C.uintptr_t(session), C.uint(bits), C.uint(algId), C.uint(index), data, l, &handle)
	if rv != SDR_OK {
		return nil, uintptr(0), errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(*l)), uintptr(handle), nil
}

func (ctx *Ctx) ImportKeyWithKEK(session uintptr, algId, index uint, key []byte) (uintptr, error) {
	var handle unsafe.Pointer
	rv := C.YX_SDF_ImportKeyWithKEKForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algId), C.uint(index), cMessage(key), C.uint(len(key)), &handle)
	if rv != SDR_OK {
		return uintptr(0), errors.New(Error(rv).Error())
	}
	return uintptr(handle), nil
}

func (ctx *Ctx) ImportKey(session uintptr, pucKey []byte) (uintptr, error) {
	l := len(pucKey)
	var ret unsafe.Pointer
	rv := C.YX_SDF_ImportKeyForSDK(ctx.ctx, C.uintptr_t(session), cMessage(pucKey), C.uint(l), &ret)
	if rv != SDR_OK {
		return uintptr(0), errors.New(Error(rv).Error())
	}
	return uintptr(ret), nil
}

func (ctx *Ctx) DestroyKey(session uintptr, keyh uintptr) error {
	rv := C.YX_SDF_DestroyKeyForSDK(ctx.ctx, C.uintptr_t(session), C.uintptr_t(keyh))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) ExternalPublicKeyOperationRSA(session uintptr, pub *RSAPublicKey, data []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("pub key not be nil")
	}
	pubKey := C.ToRSAPublicKeyForSDK(C.uint(pub.Bits), unsafe.Pointer(&pub.M[0]), unsafe.Pointer(&pub.E[0]))
	defer C.free(unsafe.Pointer(pubKey))
	output := C.NewUcharForSDK(C.int(len(data) * 2))
	defer C.free(unsafe.Pointer(output))
	l := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(l))
	rv := C.YX_SDF_ExternalPublicKeyOperation_RSAForSDK(ctx.ctx, C.uintptr_t(session), pubKey, cMessage(data), C.uint(len(data)), output, l)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(output), C.int(*l)), nil
}

func (ctx *Ctx) ExternalPrivateKeyOperationRSA(session uintptr, key *RSAPrivateKey, plain []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key not be nil")
	}
	var data C.uchar
	decLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(decLen))
	priv := C.ToRSAPrivateKeyForSDK(C.uint(key.Bits), unsafe.Pointer(&key.RSAPublicKey.M[0]), unsafe.Pointer(&key.RSAPublicKey.E[0]),
		unsafe.Pointer(&key.D[0]), unsafe.Pointer(&key.Prime[0][0]), unsafe.Pointer(&key.Prime[1][0]),
		unsafe.Pointer(&key.PExp[0][0]), unsafe.Pointer(&key.PExp[1][0]), unsafe.Pointer(&key.Coef[0]))
	defer C.free(unsafe.Pointer(priv))

	// TODO 目前江南天安这个接口并不是标准接口的形式
	rv := C.YX_SDF_ExternalPrivateKeyOperation_RSAForSDK(ctx.ctx, C.uintptr_t(session), priv, cMessage(plain), C.uint(len(plain)), &data, decLen)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(&data), C.int(*decLen)), nil
}

func (ctx *Ctx) InternalPublicKeyOperationRSA(session uintptr, index uint, data []byte) ([]byte, error) {
	output := C.NewUcharForSDK(C.int(len(data) * 2))
	defer C.free(unsafe.Pointer(output))
	l := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(l))
	rv := C.YX_SDF_InternalPublicKeyOperation_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(index), cMessage(data), C.uint(len(data)), output, l)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(output), C.int(*l)), nil
}
func (ctx *Ctx) InternalPrivateKeyOperationRSA(session uintptr, index uint, data []byte) ([]byte, error) {
	output := C.NewUcharForSDK(C.int(len(data) * 2))
	defer C.free(unsafe.Pointer(output))
	l := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(l))
	rv := C.YX_SDF_InternalPrivateKeyOperation_RSAForSDK(ctx.ctx, C.uintptr_t(session), C.uint(index), cMessage(data), C.uint(len(data)), output, l)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(output), C.int(*l)), nil
}

func (ctx *Ctx) InternalSignECC(session uintptr, index uint, data []byte) ([]byte, []byte, error) {
	sig := C.NewECCSignatureForSDK()
	defer C.free(unsafe.Pointer(sig))
	rv := C.YX_SDF_InternalSign_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(index), cMessage(data), C.uint(len(data)), sig)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	R := C.GoBytes(unsafe.Pointer(&sig.r[0]), ECCref_MAX_LEN)
	S := C.GoBytes(unsafe.Pointer(&sig.s[0]), ECCref_MAX_LEN)
	return R, S, nil
}

func (ctx *Ctx) InternalVerifyECC(session uintptr, index uint, data, r, s []byte) error {
	if len(r) == 0 || len(s) == 0 {
		return errors.New("R or S is invalid")
	}
	sig := C.ToECCSignatureForSDK(unsafe.Pointer(&r[0]), unsafe.Pointer(&s[0]))
	defer C.free(unsafe.Pointer(sig))
	rv := C.YX_SDF_InternalVerify_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(index), cMessage(data), C.uint(len(data)), sig)
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) ExternalSignECC(session uintptr, algoId uint, key *ECCPrivateKey, data []byte) ([]byte, []byte, error) {
	if key == nil {
		return nil, nil, errors.New("key not be nil")
	}
	sig := C.NewECCSignatureForSDK()
	defer C.free(unsafe.Pointer(sig))
	priv := C.ToECCPrivateKeyForSDK(C.uint(key.Bits), unsafe.Pointer(&key.D[0]))
	defer C.free(unsafe.Pointer(priv))
	rv := C.YX_SDF_ExternalSign_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algoId), priv, cMessage(data), C.uint(len(data)), sig)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(&sig.r[0]), ECCref_MAX_LEN), C.GoBytes(unsafe.Pointer(&sig.s[0]), ECCref_MAX_LEN), nil
}
func (ctx *Ctx) ExternalVerifyECC(session uintptr, algId uint, key *ECCPublicKey, data, r, s []byte) error {
	if key == nil || len(data) == 0 || len(r) == 0 || len(s) == 0 {
		return errors.New("pub key not be nil")
	}
	sig := C.ToECCSignatureForSDK(unsafe.Pointer(&r[0]), unsafe.Pointer(&s[0]))
	defer C.free(unsafe.Pointer(sig))
	pub := C.ToECCPublicKeyForSDK(C.uint(key.Bits), unsafe.Pointer(&key.X[0]), unsafe.Pointer(&key.Y[0]))
	defer C.free(unsafe.Pointer(pub))
	rv := C.YX_SDF_ExternalVerify_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algId), pub, cMessage(data), C.uint(len(data)), sig)
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}
func (ctx *Ctx) ExternalEncryptECC(session uintptr, algoId uint, key *ECCPublicKey, data []byte) (*ECCCipher, error) {
	if key == nil {
		return nil, errors.New("pub key not be nil")
	}
	enc := C.NewECCCipherForSDK()
	defer C.free(unsafe.Pointer(enc))
	pub := C.ToECCPublicKeyForSDK(C.uint(key.Bits), unsafe.Pointer(&key.X[0]), unsafe.Pointer(&key.Y[0]))
	defer C.free(unsafe.Pointer(pub))
	rv := C.YX_SDF_ExternalEncrypt_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algoId), pub, cMessage(data), C.uint(len(data)), enc)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return CECCCipherToGo(enc), nil
}

func (ctx *Ctx) ExternalDecryptECC(session uintptr, algoId, ISKindex uint, key *ECCPrivateKey, pucEncData *ECCCipher) ([]byte, error) {
	if pucEncData == nil {
		return nil, errors.New("pucEncData not be nil")
	}
	cpucEncData := C.ToECCCipherForSDK(unsafe.Pointer(&pucEncData.X[0]), unsafe.Pointer(&pucEncData.Y[0]), unsafe.Pointer(&pucEncData.M[0]),
		C.uint(pucEncData.L), unsafe.Pointer(&pucEncData.C[0]))
	defer C.free(unsafe.Pointer(cpucEncData))
	plain := C.NewUcharForSDK(C.int(ECC_CIPHER_MAX))
	defer C.free(unsafe.Pointer(plain))
	decLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(decLen))
	var priv C.PECCrefPrivateKey
	if key != nil {
		priv = C.ToECCPrivateKeyForSDK(C.uint(key.Bits), unsafe.Pointer(&key.D[0]))
		defer C.free(unsafe.Pointer(priv))
	} else {
		priv = C.NewNullECCPrivateKeyForSDK()
	}
	rv := C.YX_SDF_ExternalDecrypt_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algoId), C.uint(ISKindex), priv,
		cpucEncData, plain, decLen)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(plain), C.int(*decLen)), nil
}

func (ctx *Ctx) Encrypt(session uintptr, keyH uintptr, algoId uint, IV, plain []byte) ([]byte, []byte, error) {
	if len(plain) == 0 {
		return nil, nil, errors.New("plain data not be empty")
	}
	cipher := C.NewUcharForSDK(C.int(len(plain) + 15))
	defer C.free(unsafe.Pointer(cipher))
	encLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(encLen))
	var cIv unsafe.Pointer
	if len(IV) > 0 {
		cIv = C.CBytes(IV)
		defer C.free(cIv)
	}
	rv := C.YX_SDF_EncryptForSDK(ctx.ctx, C.uintptr_t(session), C.uintptr_t(keyH), C.uint(algoId), (*C.uchar)(cIv),
		cMessage(plain), C.uint(len(plain)), cipher, encLen)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(cIv, C.int(len(IV))), C.GoBytes(unsafe.Pointer(cipher), C.int(*encLen)), nil

}

func (ctx *Ctx) Decrypt(session uintptr, keyH uintptr, algoId uint, IV, cipher []byte) ([]byte, []byte, error) {
	if len(cipher) == 0 {
		return nil, nil, errors.New("cipher data not be empty")
	}
	plain := C.NewUcharForSDK(C.int(len(cipher)))
	defer C.free(unsafe.Pointer(plain))
	decLen := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(decLen))
	var cIv unsafe.Pointer
	if len(IV) > 0 {
		cIv = C.CBytes(IV)
		defer C.free(cIv)
	}
	rv := C.YX_SDF_DecryptForSDK(ctx.ctx, C.uintptr_t(session), C.uintptr_t(keyH), C.uint(algoId), (*C.uchar)(cIv),
		cMessage(cipher), C.uint(len(cipher)), plain, decLen)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(cIv, C.int(len(IV))), C.GoBytes(unsafe.Pointer(plain), C.int(*decLen)), nil

}

func (ctx *Ctx) CalculateMAC(session uintptr, keyH uintptr, algoId uint, IV, data []byte) ([]byte, []byte, error) {
	macData := C.NewUcharForSDK(C.int(len(data) * 2))
	defer C.free(unsafe.Pointer(macData))
	l := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(l))
	cIv := C.CBytes(IV)
	defer C.free(cIv)
	rv := C.YX_SDF_CalculateMACForSDK(ctx.ctx, C.uintptr_t(session), C.uintptr_t(keyH), C.uint(algoId), (*C.uchar)(cIv),
		cMessage(data), C.uint(len(data)), macData, l)
	if rv != SDR_OK {
		return nil, nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(cIv), C.int(len(IV))), C.GoBytes(unsafe.Pointer(macData), C.int(*l)), nil
}

func (ctx *Ctx) HashInit(session uintptr, algId uint, key *ECCPublicKey, pucId []byte) error {
	var pub C.PECCrefPublicKey
	if key != nil {
		pub = C.ToECCPublicKeyForSDK(C.uint(key.Bits), unsafe.Pointer(&key.X[0]), unsafe.Pointer(&key.Y[0]))
		defer C.free(unsafe.Pointer(pub))
	} else {
		pub = C.NewNullECCPublicKeyForSDK()
	}
	rv := C.YX_SDF_HashInitForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algId), pub, cMessage(pucId), C.uint(len(pucId)))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) HashUpdate(session uintptr, data []byte) error {
	d := make([]byte, len(data))
	copy(d, data)
	rv := C.YX_SDF_HashUpdateForSDK(ctx.ctx, C.uintptr_t(session), cMessage(d), C.uint(len(data)))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) HashFinal(session uintptr) ([]byte, error) {
	data := C.NewUcharForSDK(64)
	defer C.free(unsafe.Pointer(data))
	l := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(l))

	rv := C.YX_SDF_HashFinalForSDK(ctx.ctx, C.uintptr_t(session), data, l)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(*l)), nil
}

func (ctx *Ctx) CreateFile(session uintptr, fileName []byte, fileSize uint) error {
	rv := C.YX_SDF_CreateFileForSDK(ctx.ctx, C.uintptr_t(session), cMessage(fileName), C.uint(len(fileName)), C.uint(fileSize))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}
func (ctx *Ctx) ReadFile(session uintptr, fileName []byte, offset, size uint) ([]byte, error) {
	data := C.NewUcharForSDK(C.int(size))
	defer C.free(unsafe.Pointer(data))
	l := C.ToUintForSDK(C.uint(size))
	defer C.free(unsafe.Pointer(l))
	rv := C.YX_SDF_ReadFileForSDK(ctx.ctx, C.uintptr_t(session), cMessage(fileName), C.uint(len(fileName)),
		C.uint(offset), l, data)
	if rv != SDR_OK {
		return nil, errors.New(Error(rv).Error())
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(*l)), nil
}
func (ctx *Ctx) WriteFile(session uintptr, fileName []byte, offset uint, data []byte) error {
	rv := C.YX_SDF_WriteFileForSDK(ctx.ctx, C.uintptr_t(session), cMessage(fileName), C.uint(len(fileName)),
		C.uint(offset), C.uint(len(data)), cMessage(data))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) DeleteFile(session uintptr, fileName []byte) error {
	rv := C.YX_SDF_DeleteFileForSDK(ctx.ctx, C.uintptr_t(session), cMessage(fileName), C.uint(len(fileName)))
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

// 为了方便使用，组装的扩展函数
func (ctx *Ctx) ImportKeyPairECC(session uintptr, algoId uint, label string, pub *ECCPublicKey, priv *ECCPrivateKey) error {
	if pub == nil || priv == nil || len(label) == 0 {
		return errors.New("pub key and puckey not be nil")
	}
	pubKey := C.ToECCPublicKeyForSDK(C.uint(pub.Bits), unsafe.Pointer(&pub.X[0]), unsafe.Pointer(&pub.Y[0]))
	defer C.free(unsafe.Pointer(pubKey))
	privKey := C.ToECCPrivateKeyForSDK(C.uint(priv.Bits), unsafe.Pointer(&priv.D[0]))
	defer C.free(unsafe.Pointer(privKey))
	clabel := C.CString(label)
	defer C.free(unsafe.Pointer(clabel))
	rv := C.YX_SDF_ImportKeyPair_ECCForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algoId), C.uint(0), clabel, pubKey, privKey)
	if rv != SDR_OK {
		return errors.New(Error(rv).Error())
	}
	return nil
}

func (ctx *Ctx) GetIndex(session uintptr, algoId uint, label string) (uint, error) {
	if len(label) == 0 {
		return 0, errors.New("label not be empty")
	}
	index := C.NewUintForSDK()
	defer C.free(unsafe.Pointer(index))
	clabel := C.CString(label)
	defer C.free(unsafe.Pointer(clabel))
	rv := C.YX_SDF_GetIndexForSDK(ctx.ctx, C.uintptr_t(session), C.uint(algoId), clabel, index)
	if rv != SDR_OK {
		return 0, errors.New(Error(rv).Error())
	}
	return uint(*index), nil
}
