/*----------------------------------------------------------------------|
|	SDF.h -   The header file of SDF.c
|	Version :     1.0
|	Author:       by wyf.
| Description:  密码设备应用函数头文件，根据国密规范定义。
|               参见《GM/T 0018 密码设备应用接口规范》
|
|	Copyright :   Beijing JN TASS Technology Co., Ltd.
|	data:         2014-5-9. Create
|-----------------------------------------------------------------------|
|	Modify History:
|----------------------------------------------------------------------*/
#ifndef _TASS_SDF_H_
#define _TASS_SDF_H_

//#ifdef UNIX
#define SDFAPI
//#else
//#define SDFAPI _declspec (dllexport)
//#endif

/****************************************
 * NETCA 宏用于广东网证通定制的两个接口
 * SDF_InternalPrivateKeyOperation_RSA_EX
 * SDF_InternalDecrypt_ECC
 * 修改SDF_GetPrivateKeyAccessRight函数为国密函数
*/
//#define NETCA

// API允许打开的最大会话个数
#define MAX_SESSIONS     2048

// 对称算法机制

#define SGD_SM1_ECB	     0x00000101	// SM1算法ECB加密模式
#define SGD_SM1_CBC	     0x00000102	// SM1算法CBC加密模式
#define SGD_SM1_CFB	     0x00000104	// SM1算法CFB加密模式
#define SGD_SM1_OFB	     0x00000108	// SM1算法OFB加密模式
#define SGD_SM1_MAC	     0x00000110	// SM1算法MAC算法
#define SGD_SSF33_ECB    0x00000201	// SSF33算法ECB加密模式
#define SGD_SSF33_CBC    0x00000202	// SSF33算法CBC加密模式
#define SGD_SSF33_CFB    0x00000204	// SSF33算法CFB加密模式
#define SGD_SSF33_OFB    0x00000208	// SSF33算法OFB加密模式
#define SGD_SSF33_MAC    0x00000210	// SSF33算法MAC算法
#define SGD_SM4_ECB	     0x00000401	// SM4算法ECB加密模式
#define SGD_SM4_CBC	     0x00000402	// SM4算法CBC加密模式
#define SGD_SM4_CFB	     0x00000404	// SM4算法CFB加密模式
#define SGD_SM4_OFB	     0x00000408	// SM4算法OFB加密模式
#define SGD_SM4_MAC	     0x00000410	// SM4算法MAC算法

#define SGD_AES_ECB	     0x90000401	// AES算法ECB加密模式
#define SGD_AES_CBC	     0x90000402	// AES算法CBC加密模式
#define SGD_AES_CMAC     0x90000412	// AES算法CMAC算法
#define SGD_AES_GCM	     0x90000420	// AES算法GCM算法
#define SGD_DES_ECB	     0x90000101	// DES算法ECB加密模式
#define SGD_DES_CBC	     0x90000102	// DES算法CBC加密模式
#define SGD_DES_CMAC     0x90000122	// DES算法CMAC算法

#define SGD_ZUC_EEA3     0x00000801	// ZUC祖冲之加解密算法128-EEA3
#define SGD_ZUC_EIA3     0x00000802	// ZUC祖冲之MAC算法128-EIA3
#define SGD_RC4_STREAM   0x00000804 //RC4算法

// 非对称算法机制
#define SGD_RSA          0x00010000	// RSA算法

/*外加机制*/
#define SGD_RSA_SIGN_EX	 0x00010001  //导入或导出RSA签名或验证密钥时使用
#define SGD_RSA_ENC_EX   0x00010002  //导入或导出RSA加密或解密密钥时使用

#define SGD_SM2	         0x00020100	// SM2椭圆曲线密码算法

#define SGD_SM2_1        0x00020200	// SM2椭圆曲线签名算法
#define SGD_SM2_2        0x00020400	// SM2椭圆曲线密钥交换协议
#define SGD_SM2_3        0x00020800	// SM2椭圆曲线加密算法

// 摘要算法
#define SGD_SM3	         0x00000001	// SM3杂凑算法 SM3-256
#define SGD_SHA1         0x00000002	// SHA_1杂凑算法
#define SGD_SHA256       0x00000004	// SHA_256杂凑算法
#define SGD_MD5	         0x00000008	// MD5杂凑算法
#define SGD_SHA224	     0x00000010	// SHA_224杂凑算法
#define SGD_SHA384	     0x00000020	// SHA_384杂凑算法
#define SGD_SHA512	     0x00000040	// SHA_512杂凑算法

/* ECC曲线类型 */
//NIST标准
#define NIST_FP_160           1

//NIST标准
#define NIST_FP_192           2
#define NIST_FP_224           3
#define NIST_FP_256           4

//国密局标准
#define OSCCA_FP_192          5
#define OSCCA_FP_256          6
#define OSCCA_NEWFP_256       7

// ECC曲线内置算法NID
#define NID_NISTP256            415  // NIST的 P256
// Add by lch 20190822
#define NID_BRAINPOOLP192R1     923  // BrainpoolP192r1
// Add end
#define NID_BRAINPOOLP256R1     928  // BrainpoolP256r1
#define NID_FRP256V1            936  // FRP256V1
#define NID_SECP384R1           715  // SECP384R1
#define PARAID       OSCCA_NEWFP_256

// ECC密钥协商算法
#define SGD_ECDH         0x00000000 //
#define SGD_ECDH_SHA1    0x00000001 //
#define SGD_ECDH_SHA224  0x00000002 //
#define SGD_ECDH_SHA256  0x00000003 //
#define SGD_ECDH_SHA384  0x00000004 //
#define SGD_ECDH_SHA512  0x00000005 //


// 结构体定义
/***************************************************************************
* name:   设备信息结构体
* number:
*    @IssuerName：    设备厂商名称
*    @DeviceName：    设备型号
*    @DeviceSerial：  设备编号，包含：日期（8）、批次号（3）、流水号（5）
*    @DeviceVersion： 密码设备内部版本号
*    @DeviceVersion： 密码设备支持的接口规范版本号
*    @AsymAlgAbility：前4字节表示支持的算法，表示方法为非对称算法按位或的
*                     结果，后4字节表示算法最大模长，表示方法为支持模长按位或结果
*    @SymAlgAbility： 所有支持的对称算法，表示方法为对称算法标识按位或运算结果
*    @HashAlgAbility：所有支持的杂凑算法，表示方法为杂凑算法标识按位或运算结果
*    @BufferSize：    支持的最大文件存储空间（单位字节）
*    @Dmkcv:          DMK校验值

* Description：函数SDF_GetDeviceInfo使用，用于获取设备信息
* *************************************************************************/
typedef struct DeviceInfo_st {
    unsigned char    IssuerName[40];
    unsigned char    DeviceName[16];
    unsigned char    DeviceSerial[16];
    unsigned int     DeviceVersion;
    unsigned int     StandardVersion;
    unsigned int     AsymAlgAbility[2];
    unsigned int     SymAlgAbility;
    unsigned int     HashAlgAbility;
    unsigned int     BufferSize;
    unsigned int     Dmkcv[2];
} DEVICEINFO;

// RSA 结构体宏定义
#define RSAref_MAX_BITS    4096
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)


/***************************************************************************
* name:   RSA公钥结构体
* number:
*    @bits：          模长（比特数）
*    @m：             RSA公钥模N
*    @e：             RSA公钥指数E
*
* Description：RSA密钥目前支持的最大模长为4096。
*              m和e的BUFFER数据采用后对齐方式
* *************************************************************************/
typedef struct RSArefPublicKey_st {
    unsigned int     bits;
    unsigned char    m[RSAref_MAX_LEN];
    unsigned char    e[RSAref_MAX_LEN];
} RSArefPublicKey;

/***************************************************************************
* name:   RSA私钥结构体
* number:
*    @bits：          模长（比特数）
*    @m：             RSA公钥模N
*    @e：             RSA公钥指数E
*    @d：             RSA私钥指数D
*    @prime[0]：      素数P
*    @prime[1]：      素数Q
*    @pexp[0]：       (D % (P - 1) )
*    @pexp[1]：       (D % (Q - 1) )
*    @coef：          (1 / (Q % P) )
*
* Description：RSA密钥目前支持的最大模长为2048。
*              m、e、d、prime、pexp、coef的BUFFER数据采用后对齐方式
* *************************************************************************/
typedef struct RSArefPrivateKey_st {
    unsigned int     bits;
    unsigned char    m[RSAref_MAX_LEN];
    unsigned char    e[RSAref_MAX_LEN];
    unsigned char    d[RSAref_MAX_LEN];
    unsigned char    prime[2][RSAref_MAX_PLEN];
    unsigned char    pexp[2][RSAref_MAX_PLEN];
    unsigned char    coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

// ECC密钥宏定义
#define ECCref_MAX_BITS    512
#define ECCref_MAX_LEN     ((ECCref_MAX_BITS+7) / 8)

/***************************************************************************
* name:  ECC公钥结构体
* number:
*    @bits：          模长（比特数）
*    @x：             公钥x坐标
*    @y：             公钥y坐标
*
* Description：SM2密钥模长为256
*              x和y的BUFFER数据采用后对齐的方式
* *************************************************************************/
typedef struct ECCrefPublicKey_st {
    unsigned int     bits;
    unsigned char    x[ECCref_MAX_LEN];
    unsigned char    y[ECCref_MAX_LEN];
} ECCrefPublicKey;

/***************************************************************************
* name:  ECC私钥结构体
* number:
*    @bits：          模长（比特数）
*    @D：             私钥
*
* Description：SM2密钥模长为256
*              D的BUFFER数据采用后对齐方式
* *************************************************************************/
typedef struct ECCrefPrivateKey_st {
    unsigned int     bits;
    unsigned char    D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

// ECC密钥密文最大长度
#define ECC_CIPHER_MAX	1912
/***************************************************************************
* name:  ECC密文结构体
* number:
*    @x：          与y组成椭圆曲线上的点(x, y)
*    @y：          与x组成椭圆曲线上的点(x, y)
*    @M：          明文的SM3杂凑值
*    @L：          密文数据长度
*    @C：          密文数据,最长支持1912字节
*
* Description：ECC密钥加解密运算时使用
*              密文数据采用前对齐方式
* *************************************************************************/
typedef struct ECCCipher_st {
    unsigned char    x[ECCref_MAX_LEN];
    unsigned char    y[ECCref_MAX_LEN];
    unsigned char    M[32];
    unsigned int     L;
    unsigned char    C[ECC_CIPHER_MAX];
} ECCCipher;

/***************************************************************************
* name:  ECC签名结构体
* number:
*    @r：          签名r部分
*    @s：          签名s部分
*
* Description：ECC密钥签名(验证签名)运算时使用
* *************************************************************************/
typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

/***************************************************************************
* name:  密钥协商的自身数据
* number:
*    @pucSelfTmpPublicKey：            ECC公钥
*    @pucSelfTmpPrivateKey：           ECC私钥
*
* Description：ECC密钥签名(验证签名)运算时使用
* *************************************************************************/

typedef struct Agreement_st {
    unsigned int uiAgreementcode;
    unsigned int uiISKIndex;
    unsigned int uiKeyBits;
    unsigned int uiSponsorIDLength;
    unsigned char pucSelfID[ECCref_MAX_LEN * 2];
    ECCrefPublicKey  pucSelfTmpPublicKey;
    ECCrefPrivateKey pucSelfTmpPrivateKey;
} Agreement;

#define SDR_OK                               0x00000000	 // 操作成功
#define SDR_BASE                             0x01000000  // 错误码基础值
#define SDR_UNKNOWERR             SDR_BASE + 0x00000001	 // 未知错误
#define SDR_NOTSUPPORT            SDR_BASE + 0x00000002	 // 不支持的接口调用
#define SDR_COMMFAIL              SDR_BASE + 0x00000003	 // 与设备通信失败
#define SDR_HARDFAIL              SDR_BASE + 0x00000004	 // 运算模块无响应
#define SDR_OPENDEVICE            SDR_BASE + 0x00000005	 // 打开设备失败
#define SDR_OPENSESSION           SDR_BASE + 0x00000006	 // 创建会话失败
#define SDR_PARDENY               SDR_BASE + 0x00000007	 // 无私钥使用权限
#define SDR_KEYNOTEXIST           SDR_BASE + 0x00000008	 // 不存在的密钥调用
#define SDR_ALGNOTSUPPORT         SDR_BASE + 0x00000009	 // 不支持的算法调用
#define SDR_ALGMODNOTSUPPORT      SDR_BASE + 0x0000000A	 // 不支持的算法模式调用
#define SDR_PKOPERR               SDR_BASE + 0x0000000B	 // 公钥运算失败
#define SDR_SKOPERR               SDR_BASE + 0x0000000C	 // 私钥运算失败
#define SDR_SIGNERR               SDR_BASE + 0x0000000D	 // 签名运算失败
#define SDR_VERIFYERR             SDR_BASE + 0x0000000E	 // 验证签名失败
#define SDR_SYMOPERR              SDR_BASE + 0x0000000F	 // 对称算法运算失败
#define SDR_STEPERR               SDR_BASE + 0x00000010	 // 多步运算步骤错误
#define SDR_FILESIZEERR           SDR_BASE + 0x00000011	 // 文件长度超出限制
#define SDR_FILENOEXIST           SDR_BASE + 0x00000012	 // 指定的文件不存在
#define SDR_FILEOFSERR            SDR_BASE + 0x00000013	 // 文件起始位置错误
#define SDR_KEYTYPEERR            SDR_BASE + 0x00000014	 // 密钥类型错误
#define SDR_KEYERR                SDR_BASE + 0x00000015	 // 密钥错误
#define SDR_ENCDATAERR            SDR_BASE + 0x00000016	 // ECC密钥密文
#define SDR_RANDERR               SDR_BASE + 0x00000017	 // 随机数产生错误
#define SDR_PRKRERR               SDR_BASE + 0x00000018	 // 私钥使用权限获取失败
#define SDR_MACERR                SDR_BASE + 0x00000019	 // MAC运算失败
#define SDR_FILEEXITS             SDR_BASE + 0x0000001A	 // 指定的文件已经存在
#define SDR_FILEWRITEERR          SDR_BASE + 0x0000001B	 // 文件写错误
#define SDR_NUBUFFER              SDR_BASE + 0x0000001C	 // 存储空间不足
#define SDR_INARGERR              SDR_BASE + 0x0000001D	 // 输入参数错误
#define SDR_OUTARGERR             SDR_BASE + 0x0000001E	 // 输出参数错误


#define SDR_HANDLE_CLOSED         SDR_BASE + 0x0000001F //函数执行过程中，该会话已经关闭
#define SDR_HANDLE_COUNT          SDR_BASE + 0x00000020 //打开的会话太多
#define SDR_HANDLE_INVALID        SDR_BASE + 0x00000021 //指定的会话句柄无效
#define SDR_LOGIN_FAILED          SDR_BASE + 0x00000022 //获取私钥使用权限失败
#define SDR_LOGIN_REPEAT          SDR_BASE + 0x00000023 //获取私钥使用权限重复
#define SDR_NOT_LOGIN             SDR_BASE + 0x00000024 //私钥使用权限未获取
#define SDR_INPUT_LEN_ERROR       SDR_BASE + 0x00000025 //输入参数长度指示错误
#define SDR_KEYID_INVALID         SDR_BASE + 0x00000026 //指定的密钥号非法
#define SDR_MECHANISM_INVALID     SDR_BASE + 0x00000027 //机制无效
#define SDR_NOT_INITIALIZED       SDR_BASE + 0x00000028 //未调用初始化
#define SDR_ALREADY_INITIALIZED   SDR_BASE + 0x00000029 //初始化已调用
#define SDR_DEVICEHANDLE_INVALID  SDR_BASE + 0x0000002A //设备句柄无效


#define SDR_DEVICE_ERROR		      SDR_BASE + 0x0000002B
#define SDR_KEY_MEM_FULL		      SDR_BASE + 0x0000002C
#define SDR_KEY_GEN_FAIL		      SDR_BASE + 0x0000002D //产生密钥失败
#define SDR_FILE_OPR_ERR		      SDR_BASE + 0x0000002E
#define SDR_KEY_NO_EXIST		      SDR_BASE + 0x0000002F
#define SDR_MALLOC_ERR			      SDR_BASE + 0x00000030
#define SDR_DATA_INVALID		      SDR_BASE + 0x00000031
#define SDR_SM2_KEYBITS			      SDR_BASE + 0x00000032
#define SDR_SESSION_INIT              SDR_BASE + 0x00000033
#define SDR_RANDOM_GEN                SDR_BASE + 0x00000034 //产生随机数
#define SDR_KEYPAIR_LENGTH            SDR_BASE + 0x00000035 //非对称密钥的指数长度
#define SDR_PADDING_RSA               SDR_BASE + 0x00000036 // RSA padding 错误
#define SDR_UNPADDING_RSA             SDR_BASE + 0x00000037 // RSA unpadding 错误
#define SDR_HANDLE_SYMKEY_INVALID     SDR_BASE + 0x00000038 // 会话密钥句柄无效
#define SDR_READ_INI_ERR              SDR_BASE + 0x00000039 // 读取配置文件失败
#define SDR_HEADBEAT_TEST_ERR         SDR_BASE + 0x00000040 // 连接密码机心跳测试失败
#define SDR_DATA_TRANS_ERR            SDR_BASE + 0x00000041 // 数据传输错误

#define SDR_DATA_DEVINFO_ERR          SDR_BASE + 0x00000042 // 设备信息获取失败
#define SDR_DATA_GEN_RANDOM_ERR       SDR_BASE + 0x00000043 // 随机数生成失败
#define SDR_DATA_INDEX_OUT_ERR        SDR_BASE + 0x00000044 // 索引超出范围
#define SDR_HANDLE_INPUT_INVALID      SDR_BASE + 0x00000045 // 输入的句柄无效
#define SDR_DATA_PRI_ACCESS_ERR       SDR_BASE + 0x00000046 // 获取内部私钥权限失败
#define SDR_DATA_EXP_PUBKEY_ERR       SDR_BASE + 0x00000047 // 导出公钥失败
#define SDR_DATA_GEN_SESKEY_ERR       SDR_BASE + 0x00000048 // 生成会话密钥失败
#define SDR_DATA_DIGI_ENEV_ERR        SDR_BASE + 0x00000049 // 数字信封转换失败
#define SDR_DATA_GEN_AGREE_KEY_ERR    SDR_BASE + 0x00000050 // 生成协商密钥失败
#define SDR_DATA_IM_RSA_KEY_ERR       SDR_BASE + 0x00000051 // 导入RSA密钥对失败
#define SDR_DATA_IM_ECC_KEY_ERR       SDR_BASE + 0x00000052 // 导入ECC密钥对失败
#define SDR_DATA_IM_ECC_ENC_ERR       SDR_BASE + 0x00000053 // ECC公钥加密失败
#define SDR_DATA_IV_SYM_ERR           SDR_BASE + 0x00000054 // IV数据错误
#define SDR_DATA_HASH_INIT_ERR        SDR_BASE + 0x00000055 // 杂凑运算初始化失败
#define SDR_DATA_HASH_OP_ERR          SDR_BASE + 0x00000056 // 杂凑运算失败
#define SDR_DATA_CREATE_FILE_ERR      SDR_BASE + 0x00000057 // 创建文件失败
#define SDR_DATA_DELETE_FILE_ERR      SDR_BASE + 0x00000058 // 删除文件失败
/* sm2公钥或者私钥bits长度错误 */

#define SDR_DATA_EXP_KEY_SYMENC_ERR       SDR_BASE + 0x00000059
#define SDR_DATA_IMP_KEY_SYMENC_ERR		  SDR_BASE + 0x00000060
#define SDR_DATA_EXP_KEY_ASYENC_ERR       SDR_BASE + 0x00000061
#define SDR_DATA_IMP_KEY_ASYENC_ERR       SDR_BASE + 0x00000062

 // add by wyf 20190611
#define SDR_HSM_RESPONSE_RET_ERR      SDR_BASE + 0x00000059 // Server-side return Error in HSM
#define SDR_SOCK_GETADDR_ERR          SDR_BASE + 0x00000069 // socket get addr info
#define SDR_SOCK_CONNECT_ERR          SDR_BASE + 0x00000070 // socket connect out
#define SDR_SOCK_SEND_ERR             SDR_BASE + 0x00000071 // socket send
#define SDR_SOCK_RECV_ERR             SDR_BASE + 0x00000072 // socket recv
#define SDR_SOCK_SELECT_ERR           SDR_BASE + 0x00000073 // socket select
#define SDR_SOCK_TIMEOUT_ERR          SDR_BASE + 0x00000074 // socket time out
#define SDR_SOCK_RECV_MSG_ILLEGAL     SDR_BASE + 0x00000075 // socket recv message illegal
#define SDR_SOCK_SYSCALL_ERR          SDR_BASE + 0x00000076 // socket system call error
#define SDR_SOCK_SSL_ERR              SDR_BASE + 0x00000077 // socket SSL error
#define SDR_RTN_ERR_GETHOSTBYNAMEERROR SDR_BASE + 0x00000078 //

#define SDR_NO_USABLE_HSM             SDR_BASE + 0x00000081 // No HSM is available

#define NO_HANDLE_ERROR -1
#define NO_API_ERROR -2

typedef struct APIs {
	int (*openDevice)(void **);
	int (*closeDevice)(void *);
	int (*openSession)(void*, void **);
	int (*closeSession)(void *);
	int (*getDeviceInfo)(void * ,DEVICEINFO *);
	int (*generateRandom)(void *,unsigned int, unsigned char *);
	// 为兼容江南天安加密机，这个接口多了一个unsigned int参数
	int (*getPrivateKeyAccessRight)(void *,unsigned int,unsigned int, unsigned char *,unsigned int);
	// 为兼容江南天安加密机，这个接口多了一个unsigned int参数
	int (*releasePrivateKeyAccessRight)(void *,unsigned int, unsigned int);
	int (*exportSignPublicKeyRSA)(void *,unsigned int, RSArefPublicKey *);
	int (*exportEncPublicKeyRSA)(void *,unsigned int, RSArefPublicKey *);
	int (*generateKeyPairRSA)(void *,unsigned int, RSArefPublicKey *,RSArefPrivateKey *);
	int (*generateKeyWithIPKRSA)(void *,unsigned int,unsigned int,unsigned char*,unsigned int*,void **);
	int (*generateKeyWithEPKRSA)(void *,unsigned int,RSArefPublicKey *,unsigned char*,unsigned int*,void **);
	int (*importKeyWithISKRSA)(void *,unsigned int, unsigned char*, unsigned int, void **);
	int (*importKey)(void *, unsigned char *, unsigned int,void **);
	int (*exchangeDigitEnvelopeBaseOnRSA)(void *, unsigned int, RSArefPublicKey *, unsigned char *,unsigned int, unsigned char *, unsigned int *);
	int (*exportSignPublicKeyECC)(void *, unsigned int ,ECCrefPublicKey *);
	int (*exportEncPublicKeyECC)(void *, unsigned int ,ECCrefPublicKey *);
	int (*generateKeyPairECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *, ECCrefPrivateKey *);
	int (*generateKeyWithIPKECC)(void *, unsigned int, unsigned int, ECCCipher *, void **);
	int (*generateKeyWithEPKECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *, ECCCipher *, void **);
	int (*importKeyWithISKECC)(void *,unsigned int, ECCCipher *, void **);
	int (*exchangeDigitEnvelopeBaseOnECC)(void *, unsigned int,unsigned int, ECCrefPublicKey *, ECCCipher *, ECCCipher *);
    int (*generateAgreementDataWithECC)(void *, unsigned int,unsigned int, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, void **);
	int (*generateKeyWithECC)(void *,unsigned char *, unsigned int,ECCrefPublicKey *, ECCrefPublicKey *, void *, void **);
    int (*generateAgreementDataAndKeyWithECC)(void *, unsigned int,unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int,ECCrefPublicKey *, ECCrefPublicKey *,ECCrefPublicKey *, ECCrefPublicKey *, void **);
	int (*generateKeyWithKEK)(void *, unsigned int, unsigned int, unsigned int,unsigned char *, unsigned int *, void **);
	int (*importKeyWithKEK)(void *, unsigned int, unsigned int, unsigned char *, unsigned int, void **);
	int (*destroyKey)(void *, void *);
	int (*externalPublicKeyOperationRSA)(void *, RSArefPublicKey *, unsigned char *, unsigned int, unsigned char *, unsigned int*);
	int (*externalPrivateKeyOperationRSA)(void *, RSArefPrivateKey *, unsigned char *, unsigned int, unsigned char *, unsigned int*);
	int (*internalPublicKeyOperationRSA)(void *, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int*);
	int (*internalPrivateKeyOperationRSA)(void *, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int*);
    int (*externalSignECC)(void *, unsigned int, ECCrefPrivateKey *, unsigned char *, unsigned int, ECCSignature*);
	int (*externalVerifyECC)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int, ECCSignature*);
	int (*internalSignECC)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature*);
	int (*internalVerifyECC)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature*);
	int (*externalEncryptECC)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int, ECCCipher *);
	// 为兼容江南天安加密机，这个接口多了一个unsigned int参数
	int (*externalDecryptECC)(void *, unsigned int, unsigned int,ECCrefPrivateKey *, ECCCipher *, unsigned char *, unsigned int*);
	int (*encrypt)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
	int (*decrypt)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
	int (*calculateMAC)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
	int (*hashInit)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int);
	int (*hashUpdate)(void *, unsigned char *, unsigned int);
	int (*hashFinal)(void *, unsigned char *, unsigned int*);
	int (*createFile)(void *, unsigned char *, unsigned int, unsigned int);
	int (*readFile)(void *, unsigned char *, unsigned int , unsigned int, unsigned int *, unsigned char*);
	int (*writeFile)(void *, unsigned char *, unsigned int , unsigned int, unsigned int, unsigned char*);
	int (*deleteFile)(void *, unsigned char *, unsigned int);
	// 下面不是SDF标准里的接口
	int (*getIndex)(void *, unsigned int, char *, unsigned int *);
	int (*importKeyPairECC)(void *, unsigned int, unsigned int, char *, ECCrefPublicKey *, ECCrefPrivateKey*);
}sdfAPI;

typedef DEVICEINFO* PDevice;
typedef unsigned char* PUchar;
typedef RSArefPublicKey* PRSArefPublicKey;
typedef RSArefPrivateKey* PRSArefPrivateKey;
typedef ECCrefPublicKey* PECCrefPublicKey;
typedef ECCrefPrivateKey* PECCrefPrivateKey;
typedef unsigned int* PUint;
typedef ECCCipher* PECCCipher;
typedef ECCSignature* PECCSignature;

struct sdfctx {
	void *handle;
	void *deviceHandle;
	sdfAPI * api;
};
#endif // _TASS_SDF_H_
