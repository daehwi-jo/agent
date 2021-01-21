/*
	smartagent client application main page
	server : smartsphere
	data type : json
*/

package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"charlie/i0.0.2/cls"
)

var Agent_t Agent_s           // agent struct
var LastTime, LastNetTime int // report timer
var lprintf func(int, string, ...interface{}) = cls.Lprintf
var Mu *sync.RWMutex // main, routine 동시성 잠금, 해제

func Init() int {

	Mu = &sync.RWMutex{}

	var query string
	var resp int

	fname := cls.Cls_conf(os.Args)
	lprintf(4, "[INFO] smartagent start \n")

	// smartagent config set
	if App_conf(fname) < 0 {
		lprintf(1, "[ERROR] smartagent conf set error(%s) \n", fname)
		return FAIL
	}

	// init sql
	dname := SMARTAGENT_CONF + "/smartagent.db"
	cls.SqliteInit(dname)

	// create cert table
	query = fmt.Sprintf("CREATE TABLE CERT_TAB (CERT_ID varchar(40) not null, CERT_VER int(10) not null, PRIMARY KEY(CERT_ID));")
	CreateReqTableV(query)

	resp, cert_ts := SqlSelectCert("")
	if resp > 0 {
		for i := 0; i < len(cert_ts); i++ {
			var cert_t cert_s
			cert_t.certId = cert_ts[i].CertId
			cert_t.certVer = cert_ts[i].CertVer

			Agent_t.cert_t = append(Agent_t.cert_t, cert_t)
		}
	}

	// create edge table
	query = fmt.Sprintf("CREATE TABLE EDGE_TAB (EDGE_ID int(10) not null, UUID varchar(40) not null, PRIMARY KEY(EDGE_ID));")
	CreateReqTableV(query)

	resp = SqlSelectEdge()
	if resp > 0 && len(Agent_t.uuId) == 0 {
		lprintf(4, "[INFO] edge table select fail, make info \n")

		resp, uuid := RunCmd_S("uuidgen")
		if resp < 0 {
			lprintf(1, "[FAIL] smartagent uuid make fail \n")
			return FAIL
		}
		lprintf(4, "[INFO] smartagent make uuid(%s) \n", uuid)

		// default setting
		Agent_t.uuId = uuid

		lprintf(4, "[INFO] SqlUpdateEdge INSERT \n")
		if SqlStatementEdge(INSERT) < 0 {
			lprintf(1, "[ERROR] edge table insert error \n")
			return FAIL
		}
	}

	if FileExist(SMARTAGENT_PATH + "/uuid") {

		resp, uuid := RunCmd_S("uuidgen")
		if resp < 0 {
			lprintf(1, "[FAIL] smartagent uuid make fail \n")
			return FAIL
		}
		lprintf(4, "[INFO] smartagent make reset uuid(%s) \n", uuid)

		// default setting
		Agent_t.uuId = uuid

		if SqlStatementEdge(UPDATE) < 0 {
			lprintf(1, "[ERROR] edge table insert error \n")
			return FAIL
		}

		FileDel(SMARTAGENT_PATH + "/uuid")
	}

	// create plugin table
	query = fmt.Sprintf("CREATE TABLE PLUGIN_TAB (PLUGIN_ID varchar(40) not null, PLUGIN_VER int(10) not null, PROFILE_ID varchar(40) not null, PROFILE_VER int(10) not null, PLUGIN_STATE int(10) not null,PLUGIN_NAME varchar(20) not null,PLUGIN_NICNAME varchar(20) not null,PRIMARY KEY(PLUGIN_ID));")
	CreateReqTableV(query)

	resp, plugin_ts := SqlSelectPlugin()
	if resp > 0 && len(plugin_ts) == 0 {

		resp, pi := setAgentPlg(fname)
		if resp < 0 {
			lprintf(1, "[ERROR] plugin info read error (%s) \n", fname)
			return FAIL
		}

		if initPlugin(Agent_t.plgId, Agent_t.proId, "smartagent", Agent_t.plgVer, Agent_t.proVer) < 0 {
			lprintf(1, "[ERROR] sql smartagent insert fail \n")
			return FAIL
		}

		if len(pi.plgName) > 0 {
			if initPlugin(pi.plgId, pi.proId, pi.plgName, pi.plgVer, pi.proVer) < 0 {
				lprintf(1, "[ERROR] sql plugin %s insert fail \n", pi.plgId)
				return FAIL
			}
		}

	}

	//setting agent struct
	lprintf(4, "[INFO]plugin data read, set in agent struct \n")
	for i := 0; i < len(plugin_ts); i++ {
		var plugin_t plugin_s

		plugin_t.plgName = plugin_ts[i].PluginName
		plugin_t.nicName = plugin_ts[i].PluginNicName

		plugin_t.plgId = plugin_ts[i].PluginId
		plugin_t.plgVer = plugin_ts[i].PluginVer

		plugin_t.proId = plugin_ts[i].ProfileId
		plugin_t.proVer = plugin_ts[i].ProfileVer

		plugin_t.plgState = plugin_ts[i].PluginState
		plugin_t.plgNowState = YES

		if plugin_ts[i].PluginName == "smartagent" {
			//lprintf(4, "[INFO] smartagent plugin id(%d), plugin ver(%d) \n", plugin_ts[i].PluginId, plugin_ts[i].PluginVer)
			Agent_t.plgId = plugin_ts[i].PluginId
			Agent_t.plgVer = plugin_ts[i].PluginVer
			Agent_t.proId = plugin_ts[i].ProfileId
			Agent_t.proVer = plugin_ts[i].ProfileVer
		}

		for j := 0; j < len(Agent_t.nic_t); j++ {
			if Agent_t.nic_t[j].nicName == plugin_t.nicName {
				Agent_t.nic_t[j].plugin_t = append(Agent_t.nic_t[j].plugin_t, plugin_t)
				break
			}
		}
	}

	// uuid set
	cls.SetUuid(Agent_t.uuId)

	// td-agent conf set
	setLogCollector()

	// 장비 상태 체크
	go devStateCheck()

	if initFirewall() < 0 {
		lprintf(1, "[ERROR] init Firewall fail \n")
		return FAIL
	}

	_, Agent_t.defVer = floodToDevice()     // flood rull to device
	_, Agent_t.fireVer = xmlQueryToDevice() // user rull to device

	// smartagent Agent_t print
	PrintAgent()

	return SUCCESS

}

func sub_main() {

	if Init() < 0 {
		return
	}

	// smartagent listen
	/*
		pages := []cls.AppPages{
			{cls.GET, "/smartagent/notify", doNotify, nil},     // 종합
			{cls.GET, "/smartagent/notifire", doNotifire, nil}, // 시스템 방화벽 룰
			{cls.GET, "/smartagent/stat", doStat, nil},
			{cls.GET, "/smartagent/uuid", doUuid, nil},
			{cls.GET, "/smartagent/getPublic", doPublic, nil},
		}
		go cls.Http_start(pages, nil)
	*/

	// tcp listen
	go doNotifyTcp(Agent_t.agentPort)

	for {

		nowTime := int(time.Now().Unix())
		if LastTime == 0 {
			LastTime = nowTime - Agent_t.reportInterval
			LastNetTime = nowTime - Agent_t.reportInterval - 10
		}

		// 10초 먼저 net state check, sys state check
		if nowTime-LastNetTime >= Agent_t.reportInterval {
			Mu.Lock()

			lprintf(4, "[INFO] report cycle start \n")

			LastNetTime = nowTime
			lprintf(4, "[INFO] net interface state check start \n")
			// net interface state check
			if netStateCheck() < 0 {
				lprintf(1, "[ERROR] timer net interface state check error\n")
			}

			lprintf(4, "[INFO] sysStateCheck check start \n")
			if sysStateCheck() < 0 {
				lprintf(1, "[ERROR] timer sys info state check error\n")
			}

			Mu.Unlock()
		}

		// 30(s) plugin state check, send report message
		if nowTime-LastTime >= Agent_t.reportInterval {
			Mu.Lock()
			LastTime = nowTime
			lprintf(4, "[INFO] plugin state check start \n")
			if plgStateCheck() < 0 {
				plgStateCheck()
			}

			lprintf(4, "[INFO] make report json start \n")
			jsonBytes := makeReqJson()

			lprintf(4, "[INFO] Http_client start \n")
			resp, err := cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/report", jsonBytes, true)
			if err != nil {
				lprintf(1, "[ERROR] cls HttpSendRequest fail, error(%s) \n", err.Error())
				Mu.Unlock()
				continue
			}

			if parseResponse(resp) < 0 {
				lprintf(1, "[ERROR] parseResponse fail \n")
			}

			lprintf(4, "[INFO] report cycle end \n")

			Mu.Unlock()
		}

		time.Sleep(2 * time.Second)

	}
}
