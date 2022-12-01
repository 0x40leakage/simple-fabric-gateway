package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	lcpackager "github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/lifecycle"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/policydsl"
)

var (
	chaincodeID              = "basic001"
	chaincodeLabel           = "label_" + chaincodeID // label 是 LifecycleInstallCC 的唯一标识
	chaincodeVersion         = "1.0"
	chaincodeInitialSequence = int64(1)
	chaincodeGoPath          = "/Users/slackbuffer/go/src/github.com/hyperledger/fabric/fabric-samples/asset-transfer-basic/chaincode-go"

	peerEndpoint = "peer0.org1.example.com"
	orgMSP       = "Org1MSP"
)

func deployChaincode(w http.ResponseWriter, r *http.Request) {
	var err error
	if strings.HasPrefix(r.RequestURI, "/gm") {
		err = doDeployChaincode(gmConfigFilePath)
	} else {
		err = doDeployChaincode(configFilePath)
	}
	if err != nil {
		log.Println(err.Error())
		io.WriteString(w, err.Error())
		return
	}
	io.WriteString(w, "deploy chaincode ok")
}

func invokeChaincode(w http.ResponseWriter, r *http.Request) {
	var err error
	var resp []byte
	if strings.HasPrefix(r.RequestURI, "/gm") {
		resp, err = doInvokeChaincode(gmConfigFilePath)
	} else {
		resp, err = doInvokeChaincode(configFilePath)
	}
	if err != nil {
		log.Println(err.Error())
		io.WriteString(w, err.Error())
		return
	}
	io.WriteString(w, string(resp))
}

func doDeployChaincode(sdkConfigFilePath string) error {
	sdk, err := fabsdk.New(config.FromFile(sdkConfigFilePath))
	if err != nil {
		return err
	}
	defer sdk.Close()
	clientContext := sdk.Context(fabsdk.WithUser(sdkAdmin), fabsdk.WithOrg(sdkOrg))
	if clientContext == nil {
		return fmt.Errorf("failed to create client context based on organization name and administrator user")
	}
	resMgmtClient, err := resmgmt.New(clientContext)
	if err != nil {
		return fmt.Errorf("failed to create resource management client by client context: %v", err)
	}

	// package chaincode
	desc := &lcpackager.Descriptor{
		Path:  chaincodeGoPath,
		Type:  pb.ChaincodeSpec_GOLANG,
		Label: chaincodeLabel,
	}
	ccPkg, err := lcpackager.NewCCPackage(desc)
	if err != nil {
		return err
	}
	installCCReq := resmgmt.LifecycleInstallCCRequest{
		Label:   chaincodeLabel,
		Package: ccPkg,
	}

	cc, err := clientContext()
	if err != nil {
		return fmt.Errorf("failed to get client context")
	}
	ho := cc.SigningManager().GetHashOpts()

	packageID := lcpackager.ComputePackageIDWithHashOpts(installCCReq.Label, installCCReq.Package, ho)
	resp, err := resMgmtClient.LifecycleInstallCC(installCCReq, resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		return err
	}
	if packageID == resp[0].PackageID {
		log.Println("package id matched")
	} else {
		log.Println("package id mismatched!!!")
	}
	// install chaincode
	ccPkgReturned, err := resMgmtClient.LifecycleGetInstalledCCPackage(resp[0].PackageID, resmgmt.WithTargetEndpoints(peerEndpoint), resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		return err
	}
	if bytes.Equal(ccPkg, ccPkgReturned) {
		log.Println("package bytes matched")
	} else {
		log.Println("package bytes mismatched!!!")
	}
	// approve chaincode
	approveCCReq := resmgmt.LifecycleApproveCCRequest{
		Name:      chaincodeID,
		Version:   chaincodeVersion,
		PackageID: packageID,
		// PackageID:         resp[0].PackageID, // !!! https://stackoverflow.com/questions/60939652/in-hyperledger-fabric-when-i-try-to-invoke-im-getting-the-following-error-cha
		Sequence:          chaincodeInitialSequence,
		EndorsementPlugin: "escc",
		ValidationPlugin:  "vscc",
		SignaturePolicy:   policydsl.SignedByAnyMember([]string{orgMSP}),
		InitRequired:      false,
	}
	txnID, err := resMgmtClient.LifecycleApproveCC(channelName, approveCCReq, resmgmt.WithTargetEndpoints(peerEndpoint), resmgmt.WithOrdererEndpoint(ordererEndpoint), resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		return err
	}
	log.Printf("approve chaincode tx id: %s\n", txnID)
	// check commit readiness
	checkCommitRdReq := resmgmt.LifecycleCheckCCCommitReadinessRequest{
		Name:              chaincodeID,
		Version:           chaincodeVersion,
		EndorsementPlugin: "escc",
		ValidationPlugin:  "vscc",
		SignaturePolicy:   policydsl.SignedByAnyMember([]string{orgMSP}),
		Sequence:          chaincodeInitialSequence,
		InitRequired:      false,
	}
	respcr, err := resMgmtClient.LifecycleCheckCCCommitReadiness(channelName, checkCommitRdReq, resmgmt.WithTargetEndpoints(peerEndpoint), resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		return err
	}
	log.Printf("%#v\n", respcr)
	// commit chaincode
	reqcccr := resmgmt.LifecycleCommitCCRequest{
		Name:              chaincodeID,
		Version:           chaincodeVersion,
		Sequence:          chaincodeInitialSequence,
		EndorsementPlugin: "escc",
		ValidationPlugin:  "vscc",
		SignaturePolicy:   policydsl.SignedByAnyMember([]string{orgMSP}),
		InitRequired:      false,
	}
	txnIDccc, err := resMgmtClient.LifecycleCommitCC(channelName, reqcccr, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(peerEndpoint), resmgmt.WithOrdererEndpoint(ordererEndpoint))
	if err != nil {
		return err
	}
	log.Printf("approve chaincode tx id: %s\n", txnIDccc)
	// check committed chaincode
	req := resmgmt.LifecycleQueryCommittedCCRequest{
		Name: chaincodeID,
	}
	respqccc, err := resMgmtClient.LifecycleQueryCommittedCC(channelName, req, resmgmt.WithTargetEndpoints(peerEndpoint), resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		return err
	}
	log.Printf("%#v\n", respqccc[0])

	return nil
}

func doInvokeChaincode(sdkConfigFilePath string) ([]byte, error) {
	sdk, err := fabsdk.New(config.FromFile(sdkConfigFilePath))
	if err != nil {
		return nil, err
	}
	defer sdk.Close()
	channelContext := sdk.ChannelContext(channelName, fabsdk.WithUser(sdkAdmin), fabsdk.WithOrg(sdkOrg))
	cc, err := channel.New(channelContext)
	if err != nil {
		return nil, err
	}
	if _, err := cc.Execute(channel.Request{ChaincodeID: chaincodeID, Fcn: "InitLedger"}); err != nil {
		return nil, err
	}
	time.Sleep(2 * time.Second)
	cr, err := cc.Execute(channel.Request{ChaincodeID: chaincodeID, Fcn: "GetAllAssets"})
	if err != nil {
		return nil, err
	}
	return cr.Payload, nil
}
