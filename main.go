package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/network/genesisblock", createGenesisBlock)
	mux.HandleFunc("/network/channelcreatetx", createChannelCreateTx)
	mux.HandleFunc("/channel/setup", setupChannel)
	mux.HandleFunc("/chaincode/deploy", deployChaincode)
	mux.HandleFunc("/chaincode/invoke", invokeChaincode)

	mux.HandleFunc("/gm/network/genesisblock", createGenesisBlock)
	mux.HandleFunc("/gm/network/channelcreatetx", createChannelCreateTx)
	mux.HandleFunc("/gm/channel/setup", setupChannel)
	mux.HandleFunc("/gm/chaincode/deploy", deployChaincode)
	mux.HandleFunc("/gm/chaincode/invoke", invokeChaincode)

	// mux.HandleFunc("/channel/config", getFabricCryptoConfig)

	log.Fatal(http.ListenAndServe(":12345", mux))
}
