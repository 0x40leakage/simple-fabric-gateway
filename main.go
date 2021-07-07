package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/crl"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	fabmsp "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric/bccsp"
	cspsigner "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/pkg/errors"
)

const (
	configFilePath = "./config.yaml"
	channelName    = "mychannel"
	sdkOrg         = "Org1"
	sdkAdmin       = "Admin"
)

var gcli *MyClient

type MyClient struct {
	CC   *channel.Client
	EC   *event.Client
	RC   *resmgmt.Client
	MSPC *msp.Client
}

func main() {
	// genCRLsample()

	var err error
	gcli, err = New(configFilePath)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/channelconfig/insertgoodcrl", insertGoodCRL)
	mux.HandleFunc("/channelconfig/insertfrozencrl", insertFrozenCRL)
	mux.HandleFunc("/channelconfig/insertlockedcrl", insertLockedCRL)
	mux.HandleFunc("/channelconfig/insertbadcrl", insertBadCRL)
	mux.HandleFunc("/channelconfig/cleancrl", cleanCRL)
	mux.HandleFunc("/fab/operate", operateFabricResource)

	// mux.HandleFunc("/common/gencrl", genValidCRL)
	log.Fatal(http.ListenAndServe(":12345", mux))
}

func New(configFilePath string) (*MyClient, error) {
	sdk, err := fabsdk.New(config.FromFile(configFilePath))
	if err != nil {
		return nil, err
	}

	cliContext := sdk.Context(fabsdk.WithUser(sdkAdmin), fabsdk.WithOrg(sdkOrg))
	rc, err := resmgmt.New(cliContext)
	if err != nil {
		return nil, err
	}
	mspC, err := msp.New(cliContext)
	if err != nil {
		return nil, err
	}

	channelContext := sdk.ChannelContext(channelName, fabsdk.WithUser(sdkAdmin), fabsdk.WithOrg(sdkOrg))

	// 2021-03-26 07:45:47.257 UTC [endorser] SimulateProposal -> DEBU 29d [mychannel][cbcce1dd] Entry chaincode: name:"cscc"
	// 2021-03-26 07:45:47.257 UTC [endorser] callChaincode -> INFO 29e [mychannel][cbcce1dd] Entry chaincode: name:"cscc"
	// 2021-03-26 07:45:47.257 UTC [chaincode] Execute -> DEBU 29f Entry
	// 2021-03-26 07:45:47.257 UTC [cscc] Invoke -> DEBU 2a0 Invoke function: GetConfigBlock

	// initializer() lazyref.Initializer
	// defaultChannelConfigRefreshInterval   = time.Second * 90
	// fab.ChannelConfigRefresh

	cc, err := channel.New(channelContext)
	if err != nil {
		return nil, err
	}
	ec, err := event.New(channelContext, event.WithBlockEvents())
	if err != nil {
		return nil, err
	}

	return &MyClient{
		CC: cc,
		EC: ec,

		RC:   rc,
		MSPC: mspC,
	}, nil
}

// !!! func (msp *bccspmsp) setupCRLs(conf *m.FabricMSPConfig) error {

func UpdateCRLOfChannelConfig(at actionType, certPath, channelName string) error {
	cfgBlk, err := gcli.RC.QueryConfigBlockFromOrderer("mychannel", resmgmt.WithOrdererEndpoint("orderer0.example.com"))
	if err != nil {
		return err
	}
	cfgBlkPayload := cfgBlk.Data.Data[0]
	envelope := common.Envelope{}
	if err := proto.Unmarshal(cfgBlkPayload, &envelope); err != nil {
		return err
	}
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return err
	}
	cfgEnv := &common.ConfigEnvelope{}
	if err := proto.Unmarshal(payload.Data, cfgEnv); err != nil {
		return err
	}
	origCfg := cfgEnv.Config
	newCfg := proto.Clone(origCfg).(*common.Config)

	// === 更新开始
	newMSPCfgBytes := newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value
	var newMSPCfg fabmsp.MSPConfig
	if err := proto.Unmarshal(newMSPCfgBytes, &newMSPCfg); err != nil {
		return err
	}
	origFabMSPCfg := newMSPCfg.Config
	var fabMSPCfg fabmsp.FabricMSPConfig
	if err := proto.Unmarshal(origFabMSPCfg, &fabMSPCfg); err != nil {
		return err
	}
	// 限制 crl 记录只有一条
	fabMSPCfg.RevocationList = nil
	switch at {
	case ADD_VALID_CRL, ADD_FROZEN_CRL, ADD_LOCKED_CRL:
		// StdEncoding 会加 padding（=）
		// https://stackoverflow.com/a/36571117/6902525
		// crlEncoded := base64.RawStdEncoding.EncodeToString([]byte(crl))
		// log.Printf("crl encoded: %s\n", crlEncoded)

		// !!! 用 []byte 转换 string 类型的 crl 不行
		// !!! 不用编码
		crlBytes, err := genCRLInternal(at, certPath)
		if err != nil {
			return err
		}
		log.Printf("generated %s crl:\n%s\n", mapper[at], crlBytes)
		fabMSPCfg.RevocationList = append(fabMSPCfg.RevocationList, crlBytes)
	case ADD_INVALID_CRL:
		fabMSPCfg.RevocationList = append(fabMSPCfg.RevocationList, []byte(badCRL))
	case CLEAN_CRL:
	default:
		return fmt.Errorf("upsupported action type")

	}

	updatedFabMSPCfg, err := proto.Marshal(&fabMSPCfg)
	if err != nil {
		return err
	}
	newMSPCfg.Config = updatedFabMSPCfg
	newMSPCfgBytes, err = proto.Marshal(&newMSPCfg)
	if err != nil {
		return err
	}
	newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value = newMSPCfgBytes
	// === 更新结束

	// 包装
	cfgUpdt, err := resmgmt.CalculateConfigUpdate("mychannel", origCfg, newCfg)
	if err != nil {
		return err
	}
	cfgUpdtBytes, err := proto.Marshal(cfgUpdt)
	if err != nil {
		return err
	}
	var cfgUpdateEnv common.ConfigUpdateEnvelope
	cfgUpdateEnv.ConfigUpdate = cfgUpdtBytes
	cfgUpdateEnvBytes, err := proto.Marshal(&cfgUpdateEnv)
	if err != nil {
		return err
	}
	payload.Data = cfgUpdateEnvBytes
	updatedPayloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return err
	}
	envelope.Payload = updatedPayloadBytes
	updatedEnvelopeBytes, err := proto.Marshal(&envelope)
	if err != nil {
		return err
	}
	resp, err := gcli.RC.SaveChannel(resmgmt.SaveChannelRequest{
		ChannelID:     channelName,
		ChannelConfig: bytes.NewReader(updatedEnvelopeBytes),
	})
	if err != nil {
		return err
	}
	log.Printf("%#v\n", resp)

	return nil
}
func genCRLInternal(at actionType, certPath string) ([]byte, error) {
	cert, err := getX509Cert(certPath)
	if err != nil {
		return nil, err
	}

	org1CACert, err := getX509Cert(org1CACertPath)
	if err != nil {
		return nil, err
	}
	// log.Printf("Does admin1's AKI equal ca's ski? %v\n%x\n%v\n", bytes.Equal(org1AdminCert.AuthorityKeyId, org1CACert.SubjectKeyId), org1CACert.SubjectKeyId, org1CACert.SubjectKeyId)

	signer, err := genSigner(org1CACert)
	if err != nil {
		return nil, err
	}

	var exts []pkix.Extension
	switch at {
	case ADD_FROZEN_CRL, ADD_LOCKED_CRL:
		v, err := asn1.Marshal(mapper[at])
		if err != nil {
			return nil, err
		}
		ext := pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 45},
			Critical: false,
			Value:    v,
		}
		exts = append(exts, ext)
	case ADD_VALID_CRL:
	default:
		return nil, fmt.Errorf("unsupported action")
	}

	rt := time.Now().UTC()
	expiry := rt.Add(time.Hour)
	revokedCerts := []pkix.RevokedCertificate{{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: rt,
		Extensions:     exts,
	}}

	crl, err := crl.CreateGenericCRL(revokedCerts, signer, org1CACert, expiry)
	// log.Printf("%#v\n", crl)
	blk := &pem.Block{Bytes: crl, Type: "X509 CRL"}
	crlBytes := pem.EncodeToMemory(blk)
	// if err := ioutil.WriteFile("../fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/crls/crl.pem", crlBytes, 0644); err != nil {
	// 	return nil, err
	// }

	return crlBytes, nil
}

func genCRLsample() {
	certPath := fmt.Sprintf(userCertTemplate, ADMIN)
	v, _ := genCRLInternal(ADD_VALID_CRL, certPath)
	ioutil.WriteFile("crl.pem", v, 0644)
	f, _ := genCRLInternal(ADD_FROZEN_CRL, certPath)
	ioutil.WriteFile(mapper[ADD_FROZEN_CRL]+".pem", f, 0644)
	l, _ := genCRLInternal(ADD_LOCKED_CRL, certPath)
	ioutil.WriteFile(mapper[ADD_LOCKED_CRL]+".pem", l, 0644)
	log.Printf("valid, frozen, locked:\n%s\n%s\n%s\n", v, f, l)
}

// 撤销 Org1.Admin 证书
func GenCRL() (string, error) {
	admin1Org1CertPath := "/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem"
	org1AdminCert, err := getX509Cert(admin1Org1CertPath)
	if err != nil {
		return "", err
	}
	org1CACertPath := "/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem"
	// org1 ca's SKI: 7b523d6dcc5a0768dd8b18e463273470032036c4e1dcd7450e4ad26d0bcd89fa
	// [123 82 61 109 204 90 7 104 221 139 24 228 99 39 52 112 3 32 54 196 225 220 215 69 14 74 210 109 11 205 137 250]

	org1CACert, err := getX509Cert(org1CACertPath)
	if err != nil {
		return "", err
	}
	log.Printf("Does admin1's AKI equal ca's ski? %v\n%x\n%v\n", bytes.Equal(org1AdminCert.AuthorityKeyId, org1CACert.SubjectKeyId), org1CACert.SubjectKeyId, org1CACert.SubjectKeyId)

	signer, err := genSigner(org1CACert)
	if err != nil {
		return "", err
	}

	rt := time.Now().UTC()
	expiry := rt.Add(time.Hour)
	revokedCerts := []pkix.RevokedCertificate{{
		SerialNumber:   org1AdminCert.SerialNumber,
		RevocationTime: rt,
	}}

	crl, err := crl.CreateGenericCRL(revokedCerts, signer, org1CACert, expiry)
	log.Printf("%#v\n", crl)
	blk := &pem.Block{Bytes: crl, Type: "X509 CRL"}
	crlBytes := pem.EncodeToMemory(blk)

	// parseCRL(crlBytes, crl)

	return string(crlBytes), nil
}

func genSigner(cert *x509.Certificate) (crypto.Signer, error) {
	org1CAksPath := "/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/ca"
	csp, err := sw.NewDefaultSecurityLevel(org1CAksPath)
	if err != nil {
		return nil, err
	}
	return getSignerFromCert(cert, csp)
}

func getSignerFromCert(cert *x509.Certificate, csp bccsp.BCCSP) (crypto.Signer, error) {
	if csp == nil {
		return nil, errors.New("CSP was not initialized")
	}
	// get the public key in the right format
	certPubK, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to import certificate's public key")
	}
	// Get the key given the SKI value
	ski := certPubK.SKI()
	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, errors.WithMessage(err, "Could not find matching private key for SKI")
	}
	// BCCSP returns a public key if the private key for the SKI wasn't found, so
	// we need to return an error in that case.
	if !privateKey.Private() {
		return nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(ski))
	}
	// Construct and initialize the signer
	signer, err := cspsigner.New(csp, privateKey)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to load ski from bccsp")
	}
	return signer, nil
}

func getX509Cert(certPath string) (*x509.Certificate, error) {
	certPEMBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEMBytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// type authorityKeyIdentifier struct {
func parseCRL(crl []byte, orgCRL []byte) {
	// 判断 crl 内容是否一致
	block, _ := pem.Decode(crl)
	decodedCRLBytes := block.Bytes
	log.Printf("Bytes stay the same: %v\n", bytes.Equal(decodedCRLBytes, orgCRL))

	cl, err := x509.ParseCRL(crl)
	if err != nil {
		log.Println(err)
	}
	caSKIBytes := []byte{123, 82, 61, 109, 204, 90, 7, 104, 221, 139, 24, 228, 99, 39, 52, 112, 3, 32, 54, 196, 225, 220, 215, 69, 14, 74, 210, 109, 11, 205, 137, 250}
	bb, _ := asn1.Marshal(authKeyId{Id: caSKIBytes})
	log.Printf("%#v\n%v\n", cl, cl.TBSCertList.Extensions[0].Value)
	log.Println("-------", bytes.Equal(bb, cl.TBSCertList.Extensions[0].Value)) // true
	// [48 34 128 32 123 82 61 109 204 90 7 104 221 139 24 228 99 39 52 112 3 32 54 196 225 220 215 69 14 74 210 109 11 205 137 250]
}

// func printCRLaki(crl []byte) {
// 	var cl pkix.CertificateList
// 	if _, err := asn1.Unmarshal(crl, &cl); err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	log.Println(len(cl.TBSCertList.Extensions))
// }

/* func UpdateChannelConfig() {
	cfgBlk, err := gcli.RC.QueryConfigBlockFromOrderer("mychannel", resmgmt.WithOrdererEndpoint("orderer0.example.com"))
	if err != nil {
		log.Fatal(err)
	}
	cfgBlkPayload := cfgBlk.Data.Data[0]
	envelope := common.Envelope{}
	if err := proto.Unmarshal(cfgBlkPayload, &envelope); err != nil {
		log.Fatal(err)
	}
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		log.Fatal(err)
	}
	cfgEnv := &common.ConfigEnvelope{}
	if err := proto.Unmarshal(payload.Data, cfgEnv); err != nil {
		log.Fatal(err)
	}
	origMSPCfgBytes := cfgEnv.Config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value
	var mmm fabmsp.MSPConfig
	if err := proto.Unmarshal(origMSPCfgBytes, &mmm); err != nil {
		panic(err)
	}
	var nnn fabmsp.FabricMSPConfig
	if err := proto.Unmarshal(mmm.Config, &nnn); err != nil {
		log.Fatal(err)
	}
	log.Printf("nnn %#v\n\n", nnn)

	newCfg := proto.Clone(cfgEnv.Config).(*common.Config)

	mspConfigBytes := newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value
	var mspConfig fabmsp.FabricMSPConfig
	if err := proto.Unmarshal(mspConfigBytes, &mspConfig); err != nil {
		log.Fatal(err)
	}
	// log.Printf("msp config within update %#v\n\n", mspConfig)
	log.Printf("before %d\n\n", len(mspConfig.RevocationList))

	crlEncoded := base64.StdEncoding.EncodeToString([]byte(CRL))
	mspConfig.RevocationList = append(mspConfig.RevocationList, []byte(crlEncoded))
	mspConfig.RevocationList = nil
	updatedMSPConfigBytes, err := proto.Marshal(&mspConfig)
	if err != nil {
		panic(err)
	}
	newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value = updatedMSPConfigBytes

	// newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value = mspConfigBytes
	// newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSPClone"] = newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"]
	// delete(newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups, "Org1MSPClone")

	cfgUpd, err := resmgmt.CalculateConfigUpdate("mychannel", cfgEnv.Config, newCfg)
	if err != nil {
		log.Fatal(err)
	}

	tryConfirm := cfgUpd.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value
	var tc fabmsp.FabricMSPConfig
	if err := proto.Unmarshal(tryConfirm, &tc); err != nil {
		log.Fatal(err)
	}
	log.Printf("after calc update %d\n\n", len(tc.RevocationList))
	// for _, rli := range tc.RevocationList {
	// 	log.Printf("%s\n\n", string(rli))
	// }

	cfgUpdBytes, err := proto.Marshal(cfgUpd)
	if err != nil {
		log.Fatal(err)
	}
	var cfgUpdateEnv common.ConfigUpdateEnvelope
	cfgUpdateEnv.ConfigUpdate = cfgUpdBytes
	cfgUpdateEnvBytes, err := proto.Marshal(&cfgUpdateEnv)
	if err != nil {
		log.Fatal(err)
	}

	payload.Data = cfgUpdateEnvBytes
	updatedPayloadBytes, err := proto.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	envelope.Payload = updatedPayloadBytes

	updatedEnvelopeBytes, err := proto.Marshal(&envelope)
	if err != nil {
		log.Fatal(err)
	}

	// deltaMSPcfgByte := cfgUpd.WriteSet.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value
	// var deltaMSPConfig fabmsp.FabricMSPConfig
	// if err := proto.Unmarshal(deltaMSPcfgByte, &deltaMSPConfig); err != nil {
	// 	log.Fatal(err)
	// }
	// si, err := gcli.MSPC.GetSigningIdentity("Admin")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// cfgSig, err := gcli.RC.CreateConfigSignatureFromReader(si, bytes.NewReader(deltaMSPcfgByte))
	// if err != nil {
	// 	log.Fatal(err)
	// }

	resp, err := gcli.RC.SaveChannel(resmgmt.SaveChannelRequest{
		ChannelID:     "mychannel",
		ChannelConfig: bytes.NewReader(updatedEnvelopeBytes),
	})
	if err != nil {
		log.Printf("bad")
		log.Fatal(err)
	}
	log.Printf("%#v\n", resp)

	// TestCalculateConfigUpdate
}

func ConvertBlock2JSON() (string, error) {
	cfgBlk, err := gcli.RC.QueryConfigBlockFromOrderer("mychannel", resmgmt.WithOrdererEndpoint("orderer0.example.com"))
	if err != nil {
		return "", err
	}
	cfgBlkBytes, err := proto.Marshal(cfgBlk)
	if err != nil {
		return "", err
	}
	msgType := proto.MessageType("common.Block")
	if msgType == nil {
		return "", errors.Errorf("message of type %s unknown", msgType)
	}
	msg := reflect.New(msgType.Elem()).Interface().(proto.Message)

	in, err := ioutil.ReadAll(bytes.NewReader(cfgBlkBytes))
	if err != nil {
		return "", errors.Wrapf(err, "error reading input")
	}

	err = proto.Unmarshal(in, msg)
	if err != nil {
		return "", errors.Wrapf(err, "error unmarshaling")
	}

	var buf bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf, msg)
	if err != nil {
		return "", errors.Wrapf(err, "error encoding output")
	}

	cfgBlkPayload := cfgBlk.Data.Data[0]
	envelope := common.Envelope{}
	if err := proto.Unmarshal(cfgBlkPayload, &envelope); err != nil {
		log.Fatal(err)
	}
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		log.Fatal(err)
	}
	cfgEnv := &common.ConfigEnvelope{}
	if err := proto.Unmarshal(payload.Data, cfgEnv); err != nil {
		log.Fatal(err)
	}
	newCfg := proto.Clone(cfgEnv.Config).(*common.Config)

	mspConfigBytes := newCfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups["Org1MSP"].Values[channelconfig.MSPKey].Value
	var mspConfig fabmsp.FabricMSPConfig
	if err := proto.Unmarshal(mspConfigBytes, &mspConfig); err != nil {
		log.Fatal(err)
	}

	// for _, rli := range mspConfig.RevocationList {
	// log.Printf("%s\n\n", string(rli))
	// }
	log.Printf("%#v\n\n", mspConfig)

	return buf.String(), nil
}

// func (c *ChannelConfig) QueryBlock(reqCtx reqContext.Context) (*common.Block, error) {

// 	if c.opts.Orderer != nil {
// 		return c.queryBlockFromOrderer(reqCtx)
// 	}

// 	return c.queryBlockFromPeers(reqCtx)
// }

// regi, blkCh, err := gcli.EC.RegisterBlockEvent()
// regi, blkCh, err := gcli.EC.RegisterChaincodeEvent("a", "b")
// regi, blkCh, err := gcli.EC.RegisterFilteredBlockEvent()
// regi, blkCh, err := gcli.EC.RegisterTxStatusEvent("a")
// if err != nil {
// 	panic(err)
// }
// defer gcli.EC.Unregister(regi)
// <-blkCh

// mux := http.NewServeMux()
// mux.HandleFunc("/cc/install", ccInstallHandler)

// log.Fatal(http.ListenAndServe(":12345", mux))

// qr, err := gcli.CC.Query(channel.Request{
// 	ChaincodeID: "mycc",
// 	Fcn:         "query",
// 	Args:        [][]byte{[]byte("a")},
// })
// if err != nil {
// 	log.Println(err)
// 	return
// }
// fmt.Println(qr)

// iccs, err := gcli.RC.QueryInstalledChaincodes(resmgmt.WithTargetEndpoints("peer0.org1.example.com"))
// if err != nil {
// 	log.Fatal(err)
// }
// log.Printf("%v\n", iccs)
*/
