package genesisconfig

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/pkg/errors"
	"strings"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	ob "github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/encoder"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/configtxgen/genesisconfig"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/policydsl"
)

type ConfOption func(config *cb.Config) error

func UpdateChannelConfig(oldConf *cb.Config, opts ...ConfOption) (*cb.Config, error) {

	newConf := proto.Clone(oldConf).(*cb.Config)

	if newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey] == nil {
		return nil, fmt.Errorf("channel has closed")
	}

	if newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey] == nil {
		return nil, fmt.Errorf("channel has closed")
	}

	if newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey] == nil {
		return nil, fmt.Errorf("channel has closed")
	}

	for _, opt := range opts {
		if err := opt(newConf); err != nil {
			return nil, err
		}
	}

	// 遍历整个newConf，将所有version字段归0
	resetConfigGroupVersion(newConf.ChannelGroup)

	return newConf, nil
}

func resetConfigGroupVersion(conf *cb.ConfigGroup) {
	conf.Version = 0
	for _, group := range conf.Groups {
		resetConfigGroupVersion(group)
	}
}

func AddOrdererAddrs(ordererAddrs []string) ConfOption {
	return func(config *cb.Config) error {
		return updateOrdererAddrs(ordererAddrs, config, func(ordererAddrs []string, ordererAddrsMap map[string]bool) {
			for _, addr := range ordererAddrs {
				ordererAddrsMap[addr] = true
			}
		})
	}
}

func DelOrdererAddrs(ordererAddrs []string) ConfOption {
	return func(config *cb.Config) error {
		return updateOrdererAddrs(ordererAddrs, config, func(ordererAddrs []string, ordererAddrsMap map[string]bool) {
			for _, addr := range ordererAddrs {
				delete(ordererAddrsMap, addr)
			}
		})
	}
}

func AddOrUpdateRaftNodes(raftNodes []etcdraft.Consenter) ConfOption {
	return func(config *cb.Config) error {
		return updateRaftNodes(raftNodes, config, func(raftNodes []etcdraft.Consenter, updateNodeMap map[string]*etcdraft.Consenter) {
			for _, node := range raftNodes {
				key := fmt.Sprintf("%s-%d", node.Host, node.Port)
				updateNodeMap[key] = &etcdraft.Consenter{
					Host:          node.Host,
					Port:          node.Port,
					ServerTlsCert: node.ServerTlsCert,
					ClientTlsCert: node.ClientTlsCert,
				}
			}
		})
	}
}

// TODO: DelRaftNode raft节点变动数不能大于1
func DelRaftNodes(raftNodes []etcdraft.Consenter) ConfOption {
	return func(config *cb.Config) error {
		return updateRaftNodes(raftNodes, config, func(raftNodes []etcdraft.Consenter, updateNodeMap map[string]*etcdraft.Consenter) {
			for _, node := range raftNodes {
				key := fmt.Sprintf("%s-%d", node.Host, node.Port)
				delete(updateNodeMap, key)
			}
		})
	}
}

func AddGroupOrdererOrg(ordererOrgs []*Organization) ConfOption {
	return func(config *cb.Config) error {
		for _, org := range ordererOrgs {
			policies := make(map[string]*genesisconfig.Policy)
			if org.Policies != nil {
				err := transformStruct(org.Policies, &policies)
				if err != nil {
					return err
				}
			}
			cGroup, err := encoder.NewOrdererOrgGroup(&genesisconfig.Organization{
				Name:           org.Name,
				ID:             org.ID,
				MSPDir:         org.MSPDir,
				MSPType:        DefaultMSPType,
				AdminPrincipal: genesisconfig.AdminRoleAdminPrincipal,
				Policies:       policies,
			})
			if err != nil {
				//logger.Error("Error creating ordererOrgGroup", err)
				return err
			}
			config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups[org.Name] = cGroup
		}

		return nil
	}
}

func UpdateGroupOrdererOrg(ordererOrgs []*Organization) ConfOption {
	return func(config *cb.Config) error {
		for _, org := range ordererOrgs {
			cGroup, err := encoder.NewOrdererOrgGroup(&genesisconfig.Organization{
				Name:    org.Name,
				ID:      org.ID,
				MSPDir:  org.MSPDir,
				MSPType: DefaultMSPType,
			})
			if err != nil {
				//logger.Error("Error creating ordererOrgGroup", err)
				return err
			}
			// 继承policies
			cGroup.Policies = config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups[org.Name].Policies

			config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups[org.Name] = cGroup
		}

		return nil
	}
}

func AddGroupConsortiumOrgs(consortiumOrgs map[string][]*Organization) ConfOption {
	return func(config *cb.Config) error {
		for name, orgs := range consortiumOrgs {
			var localOrgs []*genesisconfig.Organization

			for _, org := range orgs {
				policies := make(map[string]*genesisconfig.Policy)
				if org.Policies != nil {
					err := transformStruct(org.Policies, &policies)
					if err != nil {
						return err
					}
				}
				localOrgs = append(localOrgs, &genesisconfig.Organization{
					Name:           org.Name,
					ID:             org.ID,
					MSPDir:         org.MSPDir,
					MSPType:        DefaultMSPType,
					AdminPrincipal: genesisconfig.AdminRoleAdminPrincipal,
					Policies:       policies,
				})
			}

			if _, ok := config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name]; !ok {
				cgroups, err := encoder.NewConsortiumGroup(&genesisconfig.Consortium{
					Organizations: localOrgs,
				})
				if err != nil {
					return err
				}
				config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name] = cgroups
			} else {
				for _, org := range localOrgs {
					cgroup, err := encoder.NewConsortiumOrgGroup(org)
					if err != nil {
						return err
					}
					config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name].Groups[org.Name] = cgroup
				}
			}
		}

		return nil
	}
}

//  UpdateGroupConsortiumOrgs Consortium里面不放anchor，否则会继承到每个channel中去
func UpdateGroupConsortiumOrgs(consortiumOrgs map[string][]*Organization) ConfOption {
	return func(config *cb.Config) error {
		for name, orgs := range consortiumOrgs {
			var localOrgs []*genesisconfig.Organization
			for _, org := range orgs {
				localOrgs = append(localOrgs, &genesisconfig.Organization{
					Name:    org.Name,
					ID:      org.ID,
					MSPDir:  org.MSPDir,
					MSPType: DefaultMSPType,
				})
			}

			if _, ok := config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name]; !ok {
				return fmt.Errorf("Consortium %s is not exist", name)
			} else {
				for _, org := range localOrgs {
					cgroup, err := encoder.NewConsortiumOrgGroup(org)
					if err != nil {
						return err
					}
					// 继承policies
					cgroup.Policies = config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name].Groups[org.Name].Policies
					config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name].Groups[org.Name] = cgroup
				}
			}
		}

		return nil
	}
}

func DelGroupConsortiumOrgs(consortiumOrgs map[string][]*Organization) ConfOption {
	return func(config *cb.Config) error {
		for delOrgName, _ := range consortiumOrgs {
			if _, ok := config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[delOrgName]; ok {
				delete(config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups, delOrgName)
			}
		}

		return nil
	}
}

func DelConsortiumOrgsByOrgName(orgName string) ConfOption {
	return func(config *cb.Config) error {
		for key := range config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[genesisconfig.SampleConsortiumName].Groups {
			if strings.Contains(key, orgName) {
				delete(config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[genesisconfig.SampleConsortiumName].Groups, key)
			}
		}
		return nil
	}
}

func DelGroupOrdererOrg(ordererOrgNames []string) ConfOption {
	return func(config *cb.Config) error {
		for _, delOrgName := range ordererOrgNames {
			if _, ok := config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups[delOrgName]; ok {
				delete(config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups, delOrgName)
			}
		}
		return nil
	}
}

func DelGroupApplicationOrgs(applicationOrgNames []string) ConfOption {
	return func(config *cb.Config) error {
		//应用链升级肯定会影响application,系统链升级不会
		if len(applicationOrgNames) != 0 && config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] == nil {
			//logger.Errorf("channel has closed, group: %+s is empty", channelconfig.ApplicationGroupKey)
			return fmt.Errorf("channel has closed")
		}

		for _, delOrgName := range applicationOrgNames {
			if _, ok := config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[delOrgName]; ok {
				delete(config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups, delOrgName)
			}
		}

		return nil
	}
}

func AddGroupApplicationOrgs(applicationOrgs []*Organization) ConfOption {
	return func(config *cb.Config) error {
		//应用链升级肯定会影响application,系统链升级不会
		if applicationOrgs != nil && config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] == nil {
			//logger.Errorf("channel has closed, group: %+s is empty", channelconfig.ApplicationGroupKey)
			return fmt.Errorf("channel has closed")
		}

		for _, org := range applicationOrgs {
			var anchorPeers []*genesisconfig.AnchorPeer
			for _, ap := range org.AnchorPeers {
				anchorPeers = append(anchorPeers, &genesisconfig.AnchorPeer{
					Host: ap.Host,
					Port: ap.Port,
				})
			}

			policies := make(map[string]*genesisconfig.Policy)
			if org.Policies != nil {
				err := transformStruct(org.Policies, &policies)
				if err != nil {
					return err
				}
			}

			cgroup, err := encoder.NewApplicationOrgGroup(&genesisconfig.Organization{
				Name:           org.Name,
				ID:             org.ID,
				MSPDir:         org.MSPDir,
				MSPType:        DefaultMSPType,
				AnchorPeers:    anchorPeers,
				AdminPrincipal: genesisconfig.AdminRoleAdminPrincipal,
				Policies:       policies,
			})
			if err != nil {
				//logger.Error("Error creating applicationOrgGroup", err)
				return err
			}

			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name] = cgroup
		}

		return nil
	}
}

// UpdateGroupApplicationOrgs
// 1. CRL变动属于 values["MSP"], 更新MSPDir即可
// 2. AnchorPeer变动属于 values["AnchorPeers"], 更新"AnchorPeers"即可；AnchorPeers为nil表示不改动，目前anchorPeers全部为新增。
//TODO: AnchorPeer要支持删除
func UpdateGroupApplicationOrgs(applicationOrgs []*Organization) ConfOption {
	return func(config *cb.Config) error {
		if applicationOrgs != nil && config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] == nil {
			return fmt.Errorf("channel has closed")
		}

		for _, updateOrg := range applicationOrgs {
			var originAPs []*genesisconfig.AnchorPeer

			var err error
			// 继承原有的AnchorPeers
			if config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups == nil {
				//v2.5.3版本系统链配置为空，跳过证书冻结停用时更新CRL
				return nil
			} else if config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[updateOrg.Name].Values[channelconfig.AnchorPeersKey] != nil {
				originAPs, err = getAnchorPeers(config, updateOrg.Name)
				if err != nil {
					return err
				}
			}
			newAPs := originAPs
			// 去重
			originAPMap := make(map[string]*genesisconfig.AnchorPeer)
			for _, ap := range originAPs {
				originAPMap[fmt.Sprintf("%s:%d", ap.Host, ap.Port)] = ap
			}
			for _, apUrl := range updateOrg.AnchorPeers {
				if _, ok := originAPMap[fmt.Sprintf("%s:%d", apUrl.Host, apUrl.Port)]; !ok {
					newAPs = append(newAPs, &genesisconfig.AnchorPeer{
						Host: apUrl.Host,
						Port: apUrl.Port,
					})
				}
			}

			// TODO: updateOrganization中MSPDir、Name、ID等都不太可能会变动
			updateOrganization := &genesisconfig.Organization{
				Name:    updateOrg.Name,
				ID:      updateOrg.ID,
				MSPDir:  updateOrg.MSPDir,
				MSPType: DefaultMSPType,
			}

			if len(newAPs) != 0 {
				updateOrganization.AnchorPeers = newAPs
			}

			cgroup, err := encoder.NewApplicationOrgGroup(updateOrganization)
			if err != nil {
				//logger.Error("Error creating applicationOrgGroup", err)
				return err
			}
			// 继承policies
			cgroup.Policies = config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[updateOrg.Name].Policies

			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[updateOrg.Name] = cgroup
		}

		return nil
	}
}

func DelConsortiumsGroup() ConfOption {
	return func(config *cb.Config) error {
		delete(config.ChannelGroup.Groups, channelconfig.ConsortiumsGroupKey)
		return nil
	}
}

// AddApplicationGroup 用于生成创建通道的配置块，向系统链的配置块中添加Application Group
// 主要是Groups、Policies、Values字段
func AddApplicationGroup(applicationOrgs []*Organization) ConfOption {
	return func(config *cb.Config) error {
		tmp := new(cb.ConfigGroup)
		tmp.Policies = make(map[string]*cb.ConfigPolicy)
		tmp.Groups = make(map[string]*cb.ConfigGroup)
		tmp.Values = make(map[string]*cb.ConfigValue)
		addValue(tmp, channelconfig.CapabilitiesValue(map[string]bool{DefaultChannelCapability: true}), channelconfig.AdminsPolicyKey)

		policies := map[string]*genesisconfig.Policy{
			"Admins": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyAdmins),
			},
			"Writers": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyWriters),
			},
			"Readers": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyReaders),
			},
			"AnyWriters": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyWriters),
			},
			"MajorityWriters": {
				Type: DefaultPolicyType,
				Rule: string(PolicyMajorityWriters),
			},
			"AllWriters": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAllWriters),
			},
			"Endorsement": {
				Type: DefaultPolicyType,
				Rule: string(PolicyMajorityWriters),
			},
			"LifecycleEndorsement": {
				Type: DefaultPolicyType,
				Rule: string(PolicyMajorityWriters),
			},
		}
		err := encoder.AddPolicies(tmp, policies, channelconfig.AdminsPolicyKey)
		if err != nil {
			return err
		}

		tmp.ModPolicy = channelconfig.AdminsPolicyKey

		config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] = tmp

		for _, org := range applicationOrgs {
			var anchorPeers []*genesisconfig.AnchorPeer
			for _, ap := range org.AnchorPeers {
				anchorPeers = append(anchorPeers, &genesisconfig.AnchorPeer{
					Host: ap.Host,
					Port: ap.Port,
				})
			}

			policies := make(map[string]*genesisconfig.Policy)
			if org.Policies != nil {
				err := transformStruct(org.Policies, &policies)
				if err != nil {
					return err
				}
			}

			cgroup, err := encoder.NewApplicationOrgGroup(&genesisconfig.Organization{
				Name:           org.Name,
				ID:             org.ID,
				MSPDir:         org.MSPDir,
				MSPType:        DefaultMSPType,
				AnchorPeers:    anchorPeers,
				AdminPrincipal: genesisconfig.AdminRoleAdminPrincipal,
				Policies:       policies,
			})
			if err != nil {
				//logger.Error("Error creating applicationOrgGroup", err)
				return err
			}

			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name] = cgroup
		}

		return nil
	}
}

func UpdateChannelGroupValuesConsortium() ConfOption {
	return func(config *cb.Config) error {
		addValue(config.ChannelGroup, channelconfig.ConsortiumValue(DefaultConsortium), channelconfig.AdminsPolicyKey)
		return nil
	}
}

func UpdateChannelGroupPolicies() ConfOption {
	return func(config *cb.Config) error {
		config.ChannelGroup.Policies = make(map[string]*cb.ConfigPolicy)
		policies := map[string]*genesisconfig.Policy{
			"Admins": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyAdmins),
			},
			"Writers": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyWriters),
			},
			"Readers": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyReaders),
			},
			"AnyWriters": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAnyWriters),
			},
			"MajorityWriters": {
				Type: DefaultPolicyType,
				Rule: string(PolicyMajorityWriters),
			},
			"AllWriters": {
				Type: DefaultPolicyType,
				Rule: string(PolicyAllWriters),
			},
			"Endorsement": {
				Type: DefaultPolicyType,
				Rule: string(PolicyMajorityWriters),
			},
			"LifecycleEndorsement": {
				Type: DefaultPolicyType,
				Rule: string(PolicyMajorityWriters),
			},
		}
		return encoder.AddPolicies(config.ChannelGroup, policies, channelconfig.AdminsPolicyKey)
	}
}

// UpdateSystemChannelConfigToTemplateConfig 将系统链配置块做修改，添加application group和consortium，使之符合orderer的验证逻辑
func UpdateSystemChannelConfigToTemplateConfig(applicationOrgs []*Organization, Consortium string) ConfOption {
	return func(config *cb.Config) error {
		// 与 fabric/orderer/common/msgprocessor/systemchannel.go:NewChannelConfig 做相同的初始化处理
		consortiums, ok := config.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey]
		if !ok {
			return errors.Errorf("supplied system channel group does not appear to be system channel (missing consortiums group)")
		}

		if consortiums.Groups == nil {
			return errors.Errorf("system channel consortiums group appears to have no consortiums defined")
		}

		consortium, ok := consortiums.Groups[Consortium]
		if !ok {
			return errors.Errorf("supplied system channel group is missing '%s' consortium", Consortium)
		}
		if len(applicationOrgs) == 0 {
			return errors.Errorf("supplied channel creation profile does not contain an application section")
		}
		config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] = &cb.ConfigGroup{
			Groups:   map[string]*cb.ConfigGroup{},
			Policies: make(map[string]*cb.ConfigPolicy),
			Values:   make(map[string]*cb.ConfigValue),
		}
		for _, organization := range applicationOrgs {
			var ok bool
			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[organization.Name], ok = consortium.Groups[organization.Name]
			if !ok {
				return errors.Errorf("consortium %s does not contain member org %s", Consortium, organization.Name)
			}
		}

		addValue(config.ChannelGroup, channelconfig.ConsortiumValue(Consortium), channelconfig.AdminsPolicyKey)

		delete(config.ChannelGroup.Groups, channelconfig.ConsortiumsGroupKey)
		return nil
	}
}

func UpdateAnchorPeers(orgName string, anchorPeers []*AnchorPeer) ConfOption {
	return func(config *cb.Config) error {
		if len(anchorPeers) != 0 && config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] == nil {
			return fmt.Errorf("channel has closed")
		}
		var originAPs []*genesisconfig.AnchorPeer

		var err error
		// 继承原有的AnchorPeers
		if config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups == nil {
			//v2.5.3版本系统链配置为空，跳过证书冻结停用时更新CRL
			return nil
		} else if config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[orgName].Values[channelconfig.AnchorPeersKey] != nil {
			originAPs, err = getAnchorPeers(config, orgName)
			if err != nil {
				return err
			}
		}
		newAPs := originAPs

		// 去重
		originAPMap := make(map[string]*genesisconfig.AnchorPeer)
		for _, ap := range originAPs {
			originAPMap[fmt.Sprintf("%s:%d", ap.Host, ap.Port)] = ap
		}
		for _, apUrl := range anchorPeers {
			if _, ok := originAPMap[fmt.Sprintf("%s:%d", apUrl.Host, apUrl.Port)]; !ok {
				newAPs = append(newAPs, &genesisconfig.AnchorPeer{
					Host: apUrl.Host,
					Port: apUrl.Port,
				})
			}
		}

		var anchorProtos []*pb.AnchorPeer
		for _, anchorPeer := range newAPs {
			anchorProtos = append(anchorProtos, &pb.AnchorPeer{
				Host: anchorPeer.Host,
				Port: int32(anchorPeer.Port),
			})
		}

		addValue(config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[orgName], channelconfig.AnchorPeersValue(anchorProtos), channelconfig.AdminsPolicyKey)
		return nil
	}
}

func updateOrdererAddrs(ordererAddrs []string, config *cb.Config, updateFunc func([]string, map[string]bool)) error {
	oa := &cb.OrdererAddresses{}
	val := config.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value
	if err := proto.Unmarshal(val, oa); err != nil {
		return err
	}

	oc := new(ob.ConsensusType)
	consensus := config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
	if err := proto.Unmarshal(consensus, oc); err != nil {
		//logger.Error("Error Unmarshal orderer's ConsensusType", err)
		return err
	}

	if oc.Type != genesisconfig.EtcdRaft {
		return errors.New("Consensus cluster changes can only be made under the etcd consensus.")
	}

	oldCfgOrdererAddrs := oa.Addresses
	newAddrMap := make(map[string]bool)
	for _, addr := range oldCfgOrdererAddrs {
		newAddrMap[addr] = true
	}

	var newCfgOrdererAddrs []string
	updateFunc(ordererAddrs, newAddrMap)
	// go语言中map遍历不是固定顺序，依赖map遍历顺序容易导致，addrs顺序变动，导致无实际变动的channelupdate生效。
	// 保持oldCfgOrdererAddrs中顺序
	for _, addr := range oldCfgOrdererAddrs {
		if _, ok := newAddrMap[addr]; ok {
			newCfgOrdererAddrs = append(newCfgOrdererAddrs, addr)
			delete(newAddrMap, addr)
		}
	}
	for addr, _ := range newAddrMap {
		newCfgOrdererAddrs = append(newCfgOrdererAddrs, addr)
	}

	oa.Addresses = newCfgOrdererAddrs
	val, err := proto.Marshal(oa)
	if err != nil {
		return err
	}

	config.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value = val
	return nil
}

func updateRaftNodes(raftNodes []etcdraft.Consenter, config *cb.Config,
	updateFunc func([]etcdraft.Consenter, map[string]*etcdraft.Consenter)) error {
	oc := new(ob.ConsensusType)
	consensus := config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
	if err := proto.Unmarshal(consensus, oc); err != nil {
		//logger.Error("Error Unmarshal orderer's ConsensusType", err)
		return err
	}

	if oc.Type != genesisconfig.EtcdRaft {
		return errors.New("Consensus cluster changes can only be made under the etcd consensus.")
	}

	om := new(etcdraft.ConfigMetadata)
	if err := proto.Unmarshal(oc.Metadata, om); err != nil {
		//logger.Error("Error Unmarshal etcdraft's ConfigMetadata", err)
		return err
	}

	oldCfgConsenters := om.Consenters
	// 此时是旧的raftNodeMap，经过updateFunc后会变成新的。
	newNodeMap := make(map[string]*etcdraft.Consenter)
	for _, node := range om.Consenters {
		// 配置块中，raftServerCrt和raftClientCert必然是没有重复的。
		key := fmt.Sprintf("%s-%d", node.Host, node.Port)
		newNodeMap[key] = &etcdraft.Consenter{
			Host:          node.Host,
			Port:          node.Port,
			ServerTlsCert: node.ServerTlsCert,
			ClientTlsCert: node.ClientTlsCert,
		}
	}

	updateFunc(raftNodes, newNodeMap)

	var newCfgConsenters []*etcdraft.Consenter
	// go语言中map遍历不是固定顺序，依赖map遍历顺序容易导致，addrs顺序变动，导致无实际变动的channelupdate生效。
	// 保持oldCfgConsenters中顺序
	for _, node := range oldCfgConsenters {
		key := fmt.Sprintf("%s-%d", node.Host, node.Port)
		if _, ok := newNodeMap[key]; ok {
			newCfgConsenters = append(newCfgConsenters, node)
			delete(newNodeMap, key)
		}
	}
	for _, node := range newNodeMap {
		newCfgConsenters = append(newCfgConsenters, node)
	}

	// 为了防止host+port不唯一，导致的同一组织tls多次加入，导致的duplicate consenter问题，再做一层判断.
	// 目前来说，host+port在创建时，hostip就固定了，应该不会出现这个问题。
	var tempCfgConsenters []*etcdraft.Consenter
	seen := make(map[string]struct{})
	for _, consenter := range newCfgConsenters {
		serverKey := string(consenter.ServerTlsCert)
		clientKey := string(consenter.ClientTlsCert)
		_, duplicateServerCert := seen[serverKey]
		_, duplicateClientCert := seen[clientKey]
		// 如果不重复，就写到temp中
		if !(duplicateServerCert || duplicateClientCert) {
			tempCfgConsenters = append(tempCfgConsenters, consenter)
		} else {
			logger.Warnf("duplicate consenter: server cert: %s, client cert: %s\n", serverKey, clientKey)
		}
		seen[serverKey] = struct{}{}
		seen[clientKey] = struct{}{}
	}

	om.Consenters = tempCfgConsenters
	metadata, err := proto.Marshal(om)
	if err != nil {
		//logger.Error("Error marshaling etcdraft's ConfigMetadata", err)
		return err
	}

	oc.Metadata = metadata
	consensus, err = proto.Marshal(oc)
	if err != nil {
		return err
	}
	config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value = consensus
	return nil
}

func getAnchorPeers(config *cb.Config, orgname string) ([]*genesisconfig.AnchorPeer, error) {
	// pb.Config
	originApsBytes := config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[orgname].Values[channelconfig.AnchorPeersKey].Value
	originAPsProto := &pb.AnchorPeers{}
	err := proto.Unmarshal(originApsBytes, originAPsProto)
	if err != nil {
		return nil, err
	}

	var originAPs []*genesisconfig.AnchorPeer
	for _, ap := range originAPsProto.AnchorPeers {
		originAPs = append(originAPs, &genesisconfig.AnchorPeer{Host: ap.Host, Port: int(ap.Port)})
	}
	return originAPs, err
}

func ExtractRaftNodesFromConfig(oldConf *cb.Config) ([]etcdraft.Consenter, error) {
	newConf := proto.Clone(oldConf).(*cb.Config)
	oc := new(ob.ConsensusType)
	consensus := newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
	if err := proto.Unmarshal(consensus, oc); err != nil {
		//logger.Error("Error unmarshaling orderer's ConsensusType", err)
		return nil, err
	}

	if oc.Type != genesisconfig.EtcdRaft {
		return nil, nil
	}

	om := new(etcdraft.ConfigMetadata)
	if err := proto.Unmarshal(oc.Metadata, om); err != nil {
		//logger.Error("Error unmarshaling etcdraft's ConfigMetadata", err)
		return nil, err
	}

	var resData []etcdraft.Consenter
	for _, v := range om.Consenters {
		resData = append(resData, *v)
	}

	return resData, nil
}

func GetAllOrdererGroupOrgs(oldConf *cb.Config) []string {
	var orgs []string
	for orgName := range oldConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups {
		orgs = append(orgs, orgName)
	}
	return orgs
}

func GetConsensusType(config *cb.Config) (string, error) {
	oc := new(ob.ConsensusType)
	consensus := config.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
	if err := proto.Unmarshal(consensus, oc); err != nil {
		//logger.Error("Error unmarshaling orderer's ConsensusType", err)
		return "", err
	}
	return oc.Type, nil
}

// 更新application policy
func UpdateGroupApplicationStrategy(policy StrategyPolicy) ConfOption {
	return func(config *cb.Config) error {
		if config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Policies[policy.Name] == nil {
			return fmt.Errorf("can not found policy %s in application", policy.Name)
		}
		if policy.Type == 3 {
			policyEnvelope, err := policydsl.FromString(policy.Policy)
			if err != nil {
				logger.Errorf("FromString error: %s", err)
				return nil
			}
			logger.Debugf("policyEnvelope %v", policyEnvelope)
			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Policies[policy.Name].Policy.Type = int32(cb.Policy_SIGNATURE)
			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Policies[policy.Name].Policy.Value = protoutil.MarshalOrPanic(policyEnvelope)

		} else {
			rule := cb.ImplicitMetaPolicy_Rule(policy.Type)
			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Policies[policy.Name].Policy.Type = int32(cb.Policy_IMPLICIT_META)
			config.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Policies[policy.Name].Policy.Value = protoutil.MarshalOrPanic(&cb.ImplicitMetaPolicy{
				Rule:      rule,
				SubPolicy: policy.ImplicitMetaSubPolicy,
			})
		}

		return nil
	}
}

func transformStruct(from, to interface{}) error {
	buff := new(bytes.Buffer)
	enc := gob.NewEncoder(buff)
	dec := gob.NewDecoder(buff)
	if err := enc.Encode(from); err != nil {
		return err
	}
	if err := dec.Decode(to); err != nil {
		return err
	}
	return nil
}

func addValue(cg *cb.ConfigGroup, value channelconfig.ConfigValue, modPolicy string) {
	if cg.Values == nil {
		cg.Values = make(map[string]*cb.ConfigValue)
	}
	cg.Values[value.Key()] = &cb.ConfigValue{
		Value:     protoutil.MarshalOrPanic(value.Value()),
		ModPolicy: modPolicy,
	}
}
