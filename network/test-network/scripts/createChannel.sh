#!/bin/bash

CHANNEL_NAME="$1"
DELAY="$2"
MAX_RETRY="$3"
VERBOSE="$4"
BCCSP="$5"
GM_PLUGIN="$6"
: ${CHANNEL_NAME:="mychannel"}
: ${DELAY:="3"}
: ${MAX_RETRY:="5"}
: ${VERBOSE:="false"}

if [ ! -d "channel-artifacts" ]; then
	mkdir channel-artifacts
fi

# imports  
. scripts/envVar.sh $BCCSP
. scripts/utils.sh

createChannelTx() {
	set -x
	if [ "${BCCSP}" == "GM"  ]; then
		configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/${CHANNEL_NAME}.tx -channelID $CHANNEL_NAME --bccsp=${BCCSP} --gm=${GM_PLUGIN}
	elif [ "${BCCSP}" == "SW"  ]; then
		configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/${CHANNEL_NAME}.tx -channelID $CHANNEL_NAME --bccsp=${BCCSP}
	elif [ "${BCCSP}" == "MIX" ]; then
		configtxgen -configPath ./configtx-mix -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/${CHANNEL_NAME}.tx -channelID $CHANNEL_NAME --bccsp=GM --gm=${GM_PLUGIN}
	else
		fatalln "Unsupported BCCSP type" 
	fi
	res=$?
	{ set +x; } 2>/dev/null
  verifyResult $res "Failed to generate channel configuration transaction..."
}

createChannel() {
	setGlobals 1
	# Poll in case the raft leader is not set yet
	local rc=1
	local COUNTER=1
	while [ $rc -ne 0 -a $COUNTER -lt $MAX_RETRY ] ; do
		sleep $DELAY
		set -x
		peer channel create -o localhost:7050 -c $CHANNEL_NAME --ordererTLSHostnameOverride orderer.example.com -f ./channel-artifacts/${CHANNEL_NAME}.tx --outputBlock $BLOCKFILE --tls --cafile $ORDERER_CA >&log.txt
		res=$?
		{ set +x; } 2>/dev/null
		let rc=$res
		COUNTER=$(expr $COUNTER + 1)
	done
	cat log.txt
	verifyResult $res "Channel creation failed"
}

# joinChannel ORG
joinChannel() {
  ORG=$1
  setGlobals $ORG
	local rc=1
	local COUNTER=1
	## Sometimes Join takes time, hence retry
	while [ $rc -ne 0 -a $COUNTER -lt $MAX_RETRY ] ; do
    sleep $DELAY
    set -x
    peer channel join -b $BLOCKFILE >&log.txt
    res=$?
    { set +x; } 2>/dev/null
		let rc=$res
		COUNTER=$(expr $COUNTER + 1)
	done
	cat log.txt
	verifyResult $res "After $MAX_RETRY attempts, peer0.org${ORG} has failed to join channel '$CHANNEL_NAME' "
}

setAnchorPeer() {
  ORG=$1
  # 这里不传 $BCCSP 变量，CRYPTO_DIR 通过挂载方式设置
  docker exec cli ./scripts/setAnchorPeer.sh $ORG $CHANNEL_NAME
}


## Create channeltx
infoln "Generating channel create transaction '${CHANNEL_NAME}.tx'"
createChannelTx

BLOCKFILE="./channel-artifacts/${CHANNEL_NAME}.block"

## Create channel
infoln "Creating channel ${CHANNEL_NAME}"
createChannel
successln "Channel '$CHANNEL_NAME' created"

## Join all the peers to the channel
infoln "Joining org1 peer to the channel..."
joinChannel 1
# infoln "Joining org2 peer to the channel..."
# joinChannel 2
# # MIX 时一家组织有两个 peer
# if [ "${BCCSP}" == "MIX" ]; then
# 	joinChannel 11
# 	joinChannel 21
# fi

## Set the anchor peers for each org in the channel
infoln "Setting anchor peer for org1..."
setAnchorPeer 1
# infoln "Setting anchor peer for org2..."
# setAnchorPeer 2

successln "Channel '$CHANNEL_NAME' joined"
