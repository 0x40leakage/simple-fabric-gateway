
```bash
# sm
cp -r organizations/ordererOrganizations-gm organizations/ordererOrganizations
cp -r organizations/peerOrganizations-gm organizations/peerOrganizations
mkdir channel-artifacts
cp system-genesis-block/mychannel.tx-gm channel-artifacts/mychannel.tx

# cp system-genesis-block/genesis.block-gm system-genesis-block/genesis.block

./network.sh createChannel -c mychannel -b GM -x ccsgm -g ccsgm
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go -ccl go -b GM -x ccsgm -g ccsgm

export FABRIC_CFG_PATH=$PWD/configtx
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_BCCSP_DEFAULT=GM
export CORE_PEER_X509PLUGINTYPE=ccsgm
export CORE_PEER_BCCSP_GM_IMPLTYPE=ccsgm

peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n basic009 --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt -c '{"function":"InitLedger","Args":[]}'

peer chaincode query -C mychannel -n basic009 -c '{"Args":["GetAllAssets"]}'



# sw
cp -r organizations/ordererOrganizations-sw organizations/ordererOrganizations
cp -r organizations/peerOrganizations-sw organizations/peerOrganizations
mkdir channel-artifacts
cp system-genesis-block/mychannel.tx-sw channel-artifacts/mychannel.tx

# cp system-genesis-block/genesis.block-sw system-genesis-block/genesis.block

./network.sh createChannel -c mychannel
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go -ccl go
```

# Admin

export FABRIC_CFG_PATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/sampleconfig
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_CERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt
export CORE_PEER_TLS_KEY_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key
export CORE_PEER_TLS_ROOTCERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp

# User1

export FABRIC_CFG_PATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/sampleconfig
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_CERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt
export CORE_PEER_TLS_KEY_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key
export CORE_PEER_TLS_ROOTCERT_FILE=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp

ll /home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/crls

rm /home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/crls/crl.pem

## peer channel list

ChainID 为空；返回 localMsp（msp/mgnt 内部变量，不重启不会更新）

- [x] 撤销后 localMsp 不会自动重新加载，预期重启 peer 后 crl.pem 会生效，同理解除锁定后不重启且删除 crl.pem 之前还是会出在锁定状态

## peer channel getinfo -c mychannel

ChainID 为空；

- [ ] 创建通道，生成用户证书，注销用户证书

qscc/GetChainInfo