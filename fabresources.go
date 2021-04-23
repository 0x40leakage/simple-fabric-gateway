package main

import (
	"log"
	"os"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
)

func opFab() error {
	log.Println("=====write operations=====")

	ccPath := "github.com/hyperledger/fabric/_debug/chaincode/chaincode_example02/go"
	ccPkg, err := gopackager.NewCCPackage(ccPath, os.Getenv("GOPATH"))
	if err != nil {
		return err
	}
	res, err := gcli.RC.InstallCC(resmgmt.InstallCCRequest{
		Name:    "mycc",
		Path:    ccPath,
		Version: "3.3",
		Package: ccPkg,
	})
	if err != nil {
		return err
	}
	log.Printf("%#v\n", res)

	return nil
}

/*
export FABRIC_CFG_PATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/sampleconfig
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_CERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt
export CORE_PEER_TLS_KEY_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key
export CORE_PEER_TLS_ROOTCERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp


export FABRIC_CFG_PATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/sampleconfig
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_CERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt
export CORE_PEER_TLS_KEY_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key
export CORE_PEER_TLS_ROOTCERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp


*/
