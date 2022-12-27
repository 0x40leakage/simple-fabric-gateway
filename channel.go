package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	pmsp "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource/genesisconfig"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

var (
	channelName       = "mychannel"
	channelConfigPath = "/Users/slackbuffer/go/src/github.com/hyperledger/fabric/fabric-samples/test-network/channel-artifacts/mychannel.tx"

	ordererEndpoint = "orderer.example.com"
	ordererPort     = 7050
)

func setupChannel(w http.ResponseWriter, r *http.Request) {
	var err error
	if strings.HasPrefix(r.RequestURI, "/gm") {
		err = doSetupChannel(gmConfigFilePath)
	} else {
		err = doSetupChannel(configFilePath)
	}
	if err != nil {
		log.Println(err.Error())
		io.WriteString(w, err.Error())
		return
	}
	io.WriteString(w, "channel setup ok")
}

// create channel and join peers
func doSetupChannel(sdkConfigFilePath string) error {
	sdk, err := fabsdk.New(config.FromFile(sdkConfigFilePath))
	if err != nil {
		return err
	}
	defer sdk.Close()

	clientContext := sdk.Context(fabsdk.WithUser(sdkAdmin), fabsdk.WithOrg(sdkOrg))
	if clientContext == nil {
		return fmt.Errorf("failed to create client context based on organization name and administrator user")
	}
	// New returns a resource management client instance.
	resMgmtClient, err := resmgmt.New(clientContext)
	if err != nil {
		return fmt.Errorf("failed to create resource management client by client context: %v", err)
	}
	// New creates a new Client instance
	mspClient, err := mspclient.New(sdk.Context(), mspclient.WithOrg(sdkOrg))
	if err != nil {
		return fmt.Errorf("failed to create Org MSP client by specified OrgName: %v", err)
	}
	// Returns: signing identity
	adminIdentity, err := mspClient.GetSigningIdentity(sdkAdmin)
	if err != nil {
		return fmt.Errorf("failed to get the signature of the specified ID: %v", err)
	}
	// SaveChannelRequest holds parameters for save channel request
	channelReq := resmgmt.SaveChannelRequest{ChannelID: channelName, ChannelConfigPath: channelConfigPath, SigningIdentities: []pmsp.SigningIdentity{adminIdentity}}
	// save channel response with transaction ID
	_, err = resMgmtClient.SaveChannel(channelReq, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithOrdererEndpoint(ordererEndpoint))
	if err != nil {
		return fmt.Errorf("failed to create channel: %v", err)
	}
	log.Println("Create channel successful")

	// allows for peers to join existing channel with optional custom options (specific peers, filtered peers). If peer(s) are not specified in options it will default to all peers that belong to client's MSP.
	err = resMgmtClient.JoinChannel(channelName, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithOrdererEndpoint(ordererEndpoint))
	if err != nil {
		return fmt.Errorf("peers failed to join channel: %v", err)
	}
	log.Println("Peers join channel successful")
	return nil
}

func updateAnchorPeers(w http.ResponseWriter, r *http.Request) {
	var err error
	if strings.HasPrefix(r.RequestURI, "/gm") {
		err = doUpdateAnchorPeers(gmConfigFilePath)
	} else {
		err = doUpdateAnchorPeers(configFilePath)
	}
	if err != nil {
		io.WriteString(w, err.Error())
		return
	}
	io.WriteString(w, "anchor peer channel config updated")
}

func doUpdateAnchorPeers(sdkConfigFilePath string) error {
	sdk, err := fabsdk.New(config.FromFile(sdkConfigFilePath))
	if err != nil {
		return err
	}
	defer sdk.Close()

	clientContext := sdk.Context(fabsdk.WithUser(sdkAdmin), fabsdk.WithOrg(sdkOrg))
	if clientContext == nil {
		return fmt.Errorf("failed to create client context based on organization name and administrator user")
	}
	// New returns a resource management client instance.
	resMgmtClient, err := resmgmt.New(clientContext)
	if err != nil {
		return fmt.Errorf("failed to create resource management client by client context: %v", err)
	}

	mspClient, err := mspclient.New(sdk.Context(), mspclient.WithOrg(sdkOrg))
	if err != nil {
		return fmt.Errorf("failed to create Org MSP client by specified OrgName: %v", err)
	}
	adminIdentity, err := mspClient.GetSigningIdentity(sdkAdmin)
	if err != nil {
		return fmt.Errorf("failed to get the signature of the specified ID: %v", err)
	}

	sdkOrg := &genesisconfig.Organization{
		Name:    "Org1MSP",
		ID:      "Org1MSP",
		MSPDir:  sdkOrgMSPDir,
		MSPType: "bccsp",
		Policies: map[string]*genesisconfig.Policy{
			"Admins": {
				Type: "Signature",
				Rule: "OR('Org1MSP.admin')",
			},
			"Readers": {
				Type: "Signature",
				Rule: "OR('Org1MSP.admin', 'Org1MSP.peer', 'Org1MSP.client')",
			},
			"Writers": {
				Type: "Signature",
				Rule: "OR('Org1MSP.admin', 'Org1MSP.client')",
			},
			// "Endorsement": {
			// 	Type: "Signature",
			// 	Rule: "OR('Org1MSP.peer')",
			// },
		},
		AnchorPeers: []*genesisconfig.AnchorPeer{
			{
				Host: "127.0.0.1",
				Port: 7051,
			},
		},
	}
	org2 := &genesisconfig.Organization{
		Name:    "Org2MSP",
		ID:      "Org2MSP",
		MSPDir:  org2MSPDir,
		MSPType: "bccsp",
		Policies: map[string]*genesisconfig.Policy{
			"Admins": {
				Type: "Signature",
				Rule: "OR('Org2MSP.admin')",
			},
			"Readers": {
				Type: "Signature",
				Rule: "OR('Org2MSP.admin', 'Org2MSP.peer', 'Org2MSP.client')",
			},
			"Writers": {
				Type: "Signature",
				Rule: "OR('Org2MSP.admin', 'Org2MSP.client')",
			},
			// "Endorsement": {
			// 	Type: "Signature",
			// 	Rule: "OR('Org2MSP.peer')",
			// },
		},
		AnchorPeers: []*genesisconfig.AnchorPeer{
			{
				Host: "127.0.0.1",
				Port: 9051,
			},
		},
	}

	gp := &genesisconfig.Profile{
		Consortium: "SampleConsortium",
		// Policies: map[string]*genesisconfig.Policy{
		// 	"Admins": {
		// 		Type: "ImplicitMeta",
		// 		Rule: "ANY Admins",
		// 	},
		// 	"Readers": {
		// 		Type: "ImplicitMeta",
		// 		Rule: "ANY Readers",
		// 	},
		// 	"Writers": {
		// 		Type: "ImplicitMeta",
		// 		Rule: "ANY Writers",
		// 	},
		// 	"Endorsement": {
		// 		Type: "ImplicitMeta",
		// 		Rule: "ANY Writers",
		// 	},
		// },
		Application: &genesisconfig.Application{
			ACLs: map[string]string{
				"_lifecycle/CommitChaincodeDefinition": "/Channel/Application/Writers",
				"_lifecycle/QueryChaincodeDefinition":  "/Channel/Application/Readers",
				"_lifecycle/QueryNamespaceDefinitions": "/Channel/Application/Readers",
				"lscc/ChaincodeExists":                 "/Channel/Application/Readers",
				"lscc/GetDeploymentSpec":               "/Channel/Application/Readers",
				"lscc/GetChaincodeData":                "/Channel/Application/Readers",
				"lscc/GetInstantiatedChaincodes":       "/Channel/Application/Readers",
				"qscc/GetChainInfo":                    "/Channel/Application/Readers",
				"qscc/GetBlockByNumber":                "/Channel/Application/Readers",
				"qscc/GetBlockByHash":                  "/Channel/Application/Readers",
				"qscc/GetTransactionByID":              "/Channel/Application/Readers",
				"qscc/GetBlockByTxID":                  "/Channel/Application/Readers",
				"cscc/GetConfigBlock":                  "/Channel/Application/Readers",
				"cscc/GetConfigTree":                   "/Channel/Application/Readers",
				"cscc/SimulateConfigTreeUpdate":        "/Channel/Application/Readers",
				"peer/Propose":                         "/Channel/Application/Writers",
				"peer/ChaincodeToChaincode":            "/Channel/Application/Readers",
				"event/Block":                          "/Channel/Application/Readers",
				"event/FilteredBlock":                  "/Channel/Application/Readers",
			},
			Organizations: []*genesisconfig.Organization{sdkOrg, org2},
			// Policies: map[string]*genesisconfig.Policy{
			// 	"LifecycleEndorsement": {
			// 		Type: "Signature",
			// 		Rule: "OR('Org1MSP.peer')",
			// 	},
			// 	"Endorsement": {
			// 		Type: "Signature",
			// 		Rule: "OR('Org1MSP.peer')",
			// 	},
			// 	"Readers": {
			// 		Type: "ImplicitMeta",
			// 		Rule: "ANY Readers",
			// 	},
			// 	"Writers": {
			// 		Type: "ImplicitMeta",
			// 		Rule: "ANY Writers",
			// 	},
			// 	"Admins": {
			// 		Type: "ImplicitMeta",
			// 		Rule: "ANY Admins",
			// 	},
			// },
			Capabilities: map[string]bool{
				"V2_0": true,
			},
		},
	}
	apur, err := resource.CreateAnchorPeersUpdate(gp, channelName, orgMSP)
	if err != nil {
		return err
	}
	// fmt.Printf("%#v\n", *apur)
	apurEnvBytes, err := proto.Marshal(apur)
	if err != nil {
		return err
	}
	resp, err := resMgmtClient.SaveChannel(resmgmt.SaveChannelRequest{
		ChannelID:         channelName,
		ChannelConfig:     bytes.NewReader(apurEnvBytes),
		SigningIdentities: []pmsp.SigningIdentity{adminIdentity},
	}, resmgmt.WithOrdererEndpoint(ordererEndpoint))
	if err != nil {
		return err
	}
	log.Printf("%#v\n", resp)

	return nil
}
