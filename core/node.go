package core

import (
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := buildInbound(info, tag, nil)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (v *V2Core) AddNodeWithUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error {
	inBoundConfig, err := buildInbound(info, tag, users)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	if v.dispatcher != nil {
		v.dispatcher.AuditCounter.Delete(tag)
	}
	return nil
}
