package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	pmsp "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
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
