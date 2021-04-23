module github.com/hyperledger/simple-fabric-gateway

go 1.15

require (
	github.com/Shopify/sarama v1.28.0 // indirect
	github.com/cloudflare/cfssl v1.5.0
	github.com/golang/protobuf v1.3.3
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-amcl v0.0.0-20210319225857-000ace5745f9 // indirect
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23
	github.com/hyperledger/fabric-sdk-go v1.0.0
	github.com/pkg/errors v0.8.1
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.16.0 // indirect
)

replace github.com/hyperledger/fabric-sdk-go v1.0.0 => /home/ubuntu/go/src/github.com/hyperledger/fabric-sdk-go
