module github.com/hyperledger/simple-fabric-gateway

go 1.15

require (
	github.com/cloudflare/cfssl v1.5.0 // indirect
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23
	github.com/hyperledger/fabric-sdk-go v1.0.0
	go.uber.org/zap v1.16.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace (
	github.com/Hyperledger-TWGC/ccs-gm v0.1.1 => 192.168.8.1/hyperledger/ccs-gm v1.0.0-alpha1-3-yx
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23 => 192.168.8.1/hyperledger/fabric-protos-go v0.0.0-20220708032305-eae77831a89b
	github.com/hyperledger/fabric-sdk-go v1.0.0 => 192.168.8.1/hyperledger/fabric-sdk-go v1.4.11-beta1-yx.0.20221201085820-5e524107754f
	google.golang.org/grpc v1.29.1 => 192.168.8.1/hyperledger/grpc v1.29.1-alpha1-1-yx.0.20211124084356-af5d75c99c51
)
