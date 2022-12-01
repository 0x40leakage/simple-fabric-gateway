package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/network/genesisblock", createGenesisBlock) // ok
	mux.HandleFunc("/channel/setup", setupChannel)              // ok
	mux.HandleFunc("/chaincode/deploy", deployChaincode)        // ok
	mux.HandleFunc("/chaincode/invoke", invokeChaincode)        // ok

	mux.HandleFunc("/gm/network/genesisblock", createGenesisBlock) // ok
	// mux.HandleFunc("/gm/network/channelcreatetx", createChannelCreateTx)
	mux.HandleFunc("/gm/channel/setup", setupChannel)       // ok
	mux.HandleFunc("/gm/chaincode/deploy", deployChaincode) // ok
	mux.HandleFunc("/gm/chaincode/invoke", invokeChaincode) // ok

	// mux.HandleFunc("/channel/config", getFabricCryptoConfig)

	log.Fatal(http.ListenAndServe(":12345", mux))
}
