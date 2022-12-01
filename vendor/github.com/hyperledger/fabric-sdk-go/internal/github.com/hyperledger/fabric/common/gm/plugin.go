/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/ccsgm"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/xinan"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  plugin
 * @Version: 1.0.0
 * @Date: 4/29/20 11:08 上午
 */

var NewSm2 func() gm.Sm2
var NewSm3 func() gm.Sm3
var NewSm4 func() gm.Sm4
var NewSm2Curve func() gm.Sm2Curve
var logger = flogging.MustGetLogger("GM-Plugin")

func InitGMPlugin(pluginType string, pluginParams ...string) error {
	logger.Infof("InitGMPlugin: Plugin Name [%s]", pluginType)
	switch strings.ToLower(pluginType) {
	case "", "ccsgm":
		NewSm2 = ccsgm.NewSm2
		NewSm3 = ccsgm.NewSm3
		NewSm4 = ccsgm.NewSm4
		NewSm2Curve = ccsgm.NewSm2Curve
	case "xin_an":
		if len(pluginParams) < 4 {
			return fmt.Errorf("pluginParam length is wrong ")
		}

		xinanServer, err := xinan.NewHSMServer(pluginParams[0], pluginParams[1], pluginParams[2], pluginParams[3])
		if err != nil {
			return fmt.Errorf("create gm plugin xin_an server failed, %s", err)
		}

		NewSm2 = func() gm.Sm2 {
			return xinan.NewSm2(xinanServer)
		}
		NewSm3 = func() gm.Sm3 {
			return xinan.NewSm3(xinanServer)
		}
		NewSm4 = func() gm.Sm4 {
			return xinan.NewSm4(xinanServer)
		}
	default:
		return fmt.Errorf("unrecognized gm plugin type: %s", pluginType)
	}
	return nil
}
