package genesisconfig

import (
	"time"

	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/encoder"
)

const (
	ConsensusTypeSolo     = encoder.ConsensusTypeSolo
	ConsensusTypeKafka    = encoder.ConsensusTypeKafka
	ConsensusTypeEtcdRaft = encoder.ConsensusTypeEtcdRaft
	ConsensusTypePBFT     = encoder.ConsensusTypePBFT
)

// GenesisConfig ...
type GenesisConfig struct {
	ChainID                 string
	OrdererType             string
	Addresses               []string
	BatchTimeout            time.Duration
	Kafka                   Kafka
	PBFT                    *YbftConfigMetadata
	EtcdRaft                *etcdraft.ConfigMetadata
	MaxMessageCount         uint32
	AbsoluteMaxBytes        uint32
	PreferredMaxBytes       uint32
	MaxChannels             uint64
	OrdererOrganizations    []*Organization
	ConsortiumOrganizations []*Organization
	ConsortiumName          string
	AdminsPolicy            ImplicitMetaPolicy
	WritersPolicy           ImplicitMetaPolicy
	ReadersPolicy           ImplicitMetaPolicy
}

// ImplicitMetaPolicy ...
type ImplicitMetaPolicy string

// policy
const (
	PolicyAnyAdmins      ImplicitMetaPolicy = "ANY Admins"
	PolicyMajorityAdmins ImplicitMetaPolicy = "MAJORITY Admins"
	PolicyAllAdmins      ImplicitMetaPolicy = "ALL Admins"

	PolicyAnyWriters      ImplicitMetaPolicy = "ANY Writers"
	PolicyAllWriters      ImplicitMetaPolicy = "ALL Writers"
	PolicyMajorityWriters ImplicitMetaPolicy = "MAJORITY Writers"

	PolicyAnyReaders      ImplicitMetaPolicy = "ANY Readers"
	PolicyAllReaders      ImplicitMetaPolicy = "ALL Readers"
	PolicyMajorityReaders ImplicitMetaPolicy = "MAJORITY Readers"
)

const (
	DefaultMSPType               = "bccsp"
	DefaultBatchTimeout          = 5 * time.Second
	DefaultMaxMessageCount       = 10
	DefaultAbsoluteMaxBytes      = 100 * 1024 * 1024
	DefaultPreferredMaxBytes     = 512 * 1024
	DefaultChannelCapability     = "V2_0"
	DefaultOrdererCapability     = "V2_0"
	DefaultApplicationCapability = "V2_0"
	DefaultPolicyType            = "ImplicitMeta"
)

const (
	// DefaultConsortium is the name of the default consortim
	DefaultConsortium = "SampleConsortium"
)

const (
	// error
	PartFail = "partial failed"
	AllFail  = "all failed"
)

// ChannelConfig ...
type ChannelConfig struct {
	ChainID       string
	Consortium    string
	Organizations []*Organization
}
