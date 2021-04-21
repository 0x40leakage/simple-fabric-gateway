package main

import (
	"bytes"
	"log"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	fabmsp "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric/common/channelconfig"
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
	var err error
	gcli, err = New(configFilePath)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/channelconfig/insertgoodcrl", insertGoodCRL)
	mux.HandleFunc("/channelconfig/insertbadcrl", insertBadCRL)
	mux.HandleFunc("/channelconfig/cleancrl", cleanCRL)

	mux.HandleFunc("/common/gencrl", genValidCRL)
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

// func (msp *bccspmsp) setupCRLs(conf *m.FabricMSPConfig) error {

func UpdateCRLOfChannelConfig(crl, channelName string) error {
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
	// 确保 crl 记录只有一条
	fabMSPCfg.RevocationList = nil
	if crl != "" {
		// StdEncoding 会加 padding（=）
		// https://stackoverflow.com/a/36571117/6902525
		// crlEncoded := base64.RawStdEncoding.EncodeToString([]byte(crl))
		// log.Printf("crl encoded: %s\n", crlEncoded)
		// fabMSPCfg.RevocationList = append(fabMSPCfg.RevocationList, []byte(crlEncoded))

		// 不用编码
		fabMSPCfg.RevocationList = append(fabMSPCfg.RevocationList, []byte(crl))
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
