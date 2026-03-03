package node

import (
	"strconv"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	var reportmin = 0
	var devicemin = 0
	if c.info.Common.BaseConfig != nil {
		reportmin = c.info.Common.BaseConfig.NodeReportMinTraffic
		devicemin = c.info.Common.BaseConfig.DeviceOnlineMinTraffic
	}
	if c.server != nil && c.server.Config != nil {
		if c.server.Config.SubmitTrafficMinTraffic >= 0 {
			reportmin = c.server.Config.SubmitTrafficMinTraffic
		}
		if c.server.Config.SubmitAliveIPMinTraffic >= 0 {
			devicemin = c.server.Config.SubmitAliveIPMinTraffic
		}
	}
	allTraffic, _ := c.server.GetUserTrafficSlice(c.tag, 0)
	var userTraffic []panel.UserTraffic
	if reportmin <= 0 {
		userTraffic = allTraffic
	} else {
		for _, traffic := range allTraffic {
			total := traffic.Upload + traffic.Download
			if total >= int64(reportmin*1000) {
				userTraffic = append(userTraffic, traffic)
			}
		}
	}
	if len(userTraffic) > 0 {
		err = c.apiClient.ReportUserTraffic(userTraffic)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(userTraffic))
			//log.WithField("tag", c.tag).Debugf("User traffic: %+v", userTraffic)
		}
	}

	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else if len(*onlineDevice) > 0 {
		var result []panel.OnlineUser
		uidTraffic := make(map[int]int64, len(allTraffic))
		for _, traffic := range allTraffic {
			uidTraffic[traffic.UID] += traffic.Upload + traffic.Download
		}
		for _, online := range *onlineDevice {
			if uidTraffic[online.UID] >= int64(devicemin*1000) {
				result = append(result, online)
			}
		}
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		if err = c.apiClient.ReportNodeOnlineUsers(&data); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
			//log.WithField("tag", c.tag).Debugf("Online users: %+v", data)
		}
	}

	if detectLogs, reportErr := c.server.GetAndResetUserDetectLogs(c.tag); reportErr != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": reportErr,
		}).Info("Collect detect logs failed")
	} else if len(detectLogs) > 0 {
		if reportErr = c.apiClient.ReportUserDetectLogs(detectLogs); reportErr != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": reportErr,
			}).Info("Report detect logs failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d detect logs", len(detectLogs))
		}
	}

	allTraffic = nil
	userTraffic = nil
	return nil
}

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		oldMap[key] = i
	}

	for _, user := range new {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}
