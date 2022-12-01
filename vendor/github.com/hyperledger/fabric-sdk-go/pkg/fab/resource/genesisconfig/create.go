package genesisconfig

import (
	"fmt"
	"time"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/encoder"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
)

var logger = logging.NewLogger("fabsdk/core")

// NewGenesisProfile 构建生成创世块的配置
func NewGenesisProfile(conf *GenesisConfig) *Profile {
	profile := &Profile{}
	orderer := &Orderer{}
	orderer.Addresses = conf.Addresses
	orderer.OrdererType = conf.OrdererType

	orderer.BatchTimeout = conf.BatchTimeout
	if conf.BatchTimeout == time.Duration(0) {
		orderer.BatchTimeout = DefaultBatchTimeout
	}

	orderer.BatchSize = BatchSize{
		MaxMessageCount:   conf.MaxMessageCount,
		AbsoluteMaxBytes:  conf.AbsoluteMaxBytes,
		PreferredMaxBytes: conf.PreferredMaxBytes,
	}
	if conf.MaxMessageCount == 0 {
		orderer.BatchSize.MaxMessageCount = DefaultMaxMessageCount
	}
	if conf.AbsoluteMaxBytes == 0 {
		orderer.BatchSize.AbsoluteMaxBytes = DefaultAbsoluteMaxBytes
	}
	if conf.PreferredMaxBytes == 0 {
		orderer.BatchSize.PreferredMaxBytes = DefaultPreferredMaxBytes
	}

	orderer.Kafka = conf.Kafka
	orderer.PBFT = conf.PBFT
	orderer.EtcdRaft = conf.EtcdRaft
	orderer.MaxChannels = conf.MaxChannels

	ordererPolicy := make(map[string]*Policy)
	ordererPolicy["Readers"] = &Policy{Type: "ImplicitMeta", Rule: "ANY Readers"}
	ordererPolicy["Writers"] = &Policy{Type: "ImplicitMeta", Rule: "ANY Writers"}
	ordererPolicy["Admins"] = &Policy{Type: "ImplicitMeta", Rule: "ANY Admins"}
	ordererPolicy["BlockValidation"] = &Policy{Type: "ImplicitMeta", Rule: "ANY Writers"}

	orderer.Capabilities = make(map[string]bool)
	orderer.Capabilities[DefaultOrdererCapability] = true
	orderer.Policies = ordererPolicy

	profile.Orderer = orderer
	profile.Policies = ordererPolicy

	profile.Consortiums = make(map[string]*Consortium)

	var ordererOrgs []*Organization
	for _, org := range conf.OrdererOrganizations {
		ordererOrgs = append(ordererOrgs, &Organization{
			Name:     org.Name,
			ID:       org.ID,
			MSPDir:   org.MSPDir,
			MSPType:  DefaultMSPType,
			Policies: GetSignaturePolicyDefaults(org.ID),
		})
	}
	var consortiumOrgs []*Organization
	for _, org := range conf.ConsortiumOrganizations {
		consortiumOrgs = append(consortiumOrgs, &Organization{
			Name:     org.Name,
			ID:       org.ID,
			MSPDir:   org.MSPDir,
			MSPType:  DefaultMSPType,
			Policies: GetSignaturePolicyDefaults(org.ID),
		})
	}
	orderer.Organizations = ordererOrgs
	consortium := &Consortium{
		Organizations: consortiumOrgs,
	}

	if conf.ConsortiumName == "" {
		profile.Consortiums[DefaultConsortium] = consortium
	} else {
		profile.Consortiums[conf.ConsortiumName] = consortium
	}

	profile.Capabilities = make(map[string]bool)
	profile.Capabilities[DefaultChannelCapability] = true

	return profile
}

func GetSignaturePolicyDefaults(mspID string) map[string]*Policy {
	orgPolicies := make(map[string]*Policy, 3)
	orgPolicies[channelconfig.ReadersPolicyKey] = getSignedByFabricMember(mspID)
	orgPolicies[channelconfig.WritersPolicyKey] = getSignedByFabricMember(mspID)
	// TODO: admin才可以
	orgPolicies[channelconfig.AdminsPolicyKey] = getSignedByFabricAdmin(mspID)
	return orgPolicies
}

// signedByFabricMember
func getSignedByFabricMember(mspID string) *Policy {
	return &Policy{
		Type: encoder.SignaturePolicyType,
		Rule: fmt.Sprintf("OutOf(1, '%s.member')", mspID),
	}
}

// signedByFabricMember
func getSignedByFabricAdmin(mspID string) *Policy {
	return &Policy{
		Type: encoder.SignaturePolicyType,
		Rule: fmt.Sprintf("OutOf(1, '%s.admin')", mspID),
	}
}
