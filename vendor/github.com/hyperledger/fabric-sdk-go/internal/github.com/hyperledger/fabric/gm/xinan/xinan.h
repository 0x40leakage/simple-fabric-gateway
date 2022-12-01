#ifndef _XINAN_H_
#define _XINAN_H_
#define NO_HANDLE_ERROR -1
#define NO_API_ERROR -2
#define INS_PADDING_PKCS7	0x02
#define INS_MODE_CBC		(0x0200)

typedef struct SymmEncryptParam
{
	char Alg[64];
	int mode;
	unsigned char iv[32];
	int ivLen;
}SymmEncryptParam;

typedef struct XinAnAPI{
	int (*connToNetSign)(char *, int, char *, int *);
	int (*discFromNetSign)(int);
	char* (*getVersion)();
	int (*uploadCert)(int,unsigned char*, int);
	int (*certExist)(int,char*);
	int (*KPLGenP10Req)(int, char*, char*, char*, int, unsigned char*, unsigned int *);
 	int (*KPLImportCert)(int, char*, unsigned char*, unsigned int);
	int (*rawSignData)(int, unsigned char*, int, char*, char *, int, unsigned char*, int*);
	int (*rawVerifyData)(int, unsigned char*, int, char*, char *, int, unsigned char*, int);
 	int (*rawVerifyWithCert)(int, unsigned char*, int, unsigned char*, int, char *, int, unsigned char*, int);
	int (*rawEncrypt)(int, unsigned char*, int, char*, int, unsigned char*, int*);
 	int (*rawEncryptWithCert)(int, unsigned char*, int, unsigned char*, int, int, unsigned char*, int*);
	int (*rawDecrypt)(int, unsigned char*, int, char*, int, unsigned char*, int*);
	int (*hashData)(int, char*, unsigned char*, int, unsigned char*, int*);
	int (*genRandom)(int, unsigned char*, int);
	int (*encryptWithKey)(int, const unsigned char*, int, SymmEncryptParam *,const unsigned char *, int, unsigned char *, int *);
	int (*decryptWithKey)(int, const unsigned char*, int, SymmEncryptParam *,const unsigned char *, int, unsigned char *, int *);
	int (*encryptWithKeyId)(int, char*, SymmEncryptParam *, unsigned char *, int, unsigned char *, int *);
	int (*decryptWithKeyId)(int, char*, SymmEncryptParam *, unsigned char *, int, unsigned char *, int *);
}XinAnAPI;

struct xinAnCtx {
	void *handle;
	XinAnAPI * api;
};
#endif // _XINAN_H_
