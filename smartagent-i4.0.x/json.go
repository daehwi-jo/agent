/*
	CO_SERVER / RD_SERVER
	type : json
*/

package main

import (
	"encoding/json"
	_ "time"
)

type request struct {
	UuID string `json:"uuId"` // uuid gen
	//FireVer int `json:"fireVer"` // firewall rule version
	//DefVer  int `json:"defVer"`  // defence rule version (flooding, slow read)

	IspInfo string `json:"ispInfo"` // sk:on / lg:on / kt:on
	Os      string `json:"os"`
	OsBit   string `json:"osbit"`
	//Uptime  uint32 `json:"uptime"`

	Cache_t     []Cache_s     `json:"cacheState"`
	SysState_t  SysState_s    `json:"sysState"`
	NicState_t  []NicState_s  `json:"nicState"`  // nic, plugin info
	CertState_t []CertState_s `json:"certState"` // cert ver
}

type Cache_s struct {
	Domain     string       `json:"domain"`
	HostInfo_t []HostInfo_s `json:"hostCache"`
}

type HostInfo_s struct {
	Host      string `json:"host"`
	CacheSize string `json:"cache"`
}

type SysState_s struct {
	Cpu  string `json:"cpu"` // cpu usage     ex) 60
	Mem  string `json:"mem"` // memory usage  ex) 60
	Net  uint64 `json:"net"` // network usage ex) 60
	Disk string `json:"TCP"` // disk

	//LOADAVG int    `json:"LOADAVG"` // load average 1 min
}

type NicState_s struct {
	NicName  string `json:"nicName"`  // nic card name
	NicUse   int    `json:"nicUse"`   // nic card use flag (1:use, 0:not use)
	NicLink  int    `json:"nicLink"`  // nic card link flag (1:run, 0:not run)
	NicAdmin int    `json:"nicAdmin"` // nic card admin state (1:up, 0: down)
	NicMac   string `json:"nicMac"`   // nic card mac address (00:11...)
	NicIpv   int    `json:"nicIpv"`   // nic card ip version (4, 6)
	NicIP    string `json:"nicIp"`    // nic card ip (3.3.3.3)
	NicPubIP string `json:"nicPubIp"` // nic card ip (3.3.3.3)

	Plugin_t []PlgState_s `json:"plgState"`
}

type CertState_s struct {
	CertId string `json:"certId"` // certification id
	//CertVer int    `json:"certVer"` // certification version
}

type PlgState_s struct {
	PlgID    string `json:"plgId"`    // plugin id
	PlgVer   int    `json:"plgVer"`   // plugin version
	PlgName  string `json:"plgName"`  // plugin name
	PlgState int    `json:"plgState"` // plugin state (1:run or 0:down)
	ProID    string `json:"ProID"`
	ProVer   int    `json:"ProVer"`
}

// tskim
type Defence struct {
	FloodTime   int `json:"floodTime"`   // 10초 (firewall)
	FloodCnt    int `json:"floodCnt"`    // 500건
	FBlockTime  int `json:"fBlockTime"`  // 0 : 무한정 막는다 / 100 : 100초 막는다
	ReadMinSize int `json:"readMinSize"` // 최소 읽어야 하는 size (idle)
	ReadTime    int `json:"readTime"`    // 10초
	RBlockTime  int `json:"rBlockTime"`  // 0 : 무한정 막는다 / 100 : 100초 막는다
}

type response struct {
	UuID       string `json:"sphereUUID"`
	DeviceName string `json:"deviceName"`

	// tskim
	RSphere  string `json:"rSphere"`  // region sphere ip from db
	RStation string `json:"rStation"` // region station ip from db
	RDb      string `json:"rDb"`      // region db ip from db
	RCrawl   string `json:"rCrawl"`   // region crawl ip from db

	FireVer int     `json:"fireVer"` // firewall rule version
	DefVer  int     `json:"defVer"`  // defence rule version (flooding, slow read)
	DefRule Defence `json:"defRule"` // defence rule
	DefUse  int     `json:"defUse"`  // defence use -> 1 : 차단, 0 : 보고

	Operation_t []Operation_s `json:"operation"`
	Download_t  []Download_s  `json:"download"`
	//IdleDomain  []string      `json:"idledomain"`
	//DelBlack    []string      `json:"delblack"`
}

type Operation_s struct {
	Action  int    `json:"action"`  // 0:plugin install, 1:plugin update, 2:plugin delete, 3:profile update, 4:agent restart
	NicName string `json:"nicName"` // nic card name
	PlgId   string `json:"plgId"`   // plugin id
	PlgVer  int    `json:"plgVer"`  // plugin version
	PlgName string `json:"plgName"`
	ProID   string `json:"ProID"`
	ProVer  int    `json:"ProVer"`
}

type Download_s struct {
	Action int    `json:"action"` // 0:plugin install, 1:plugin update, 2:plugin delete
	CertId string `json:"certId"` // certification id
	//CertVer int    `json:"certVer"` // certification version
}

type notify struct {
	UuID   string `json:"uuId"`   // uuid gen
	Notify int    `json:"notify"` // notify (0:agent, 1: firewall, 2: idle, 3: Alive)
	Domain string `json:"domain"` // idle nginx config

	// idle cache delete
	CachePath struct {
		Domain string `json:"domain"` // naver.com
		Host   string `json:"host"`   // www
	} `json:"cachePath"`

	// crawling
	Crawling struct {
		Fqdn     string `json:"fqdn"`
		Port     string `json:"port"`
		Protocol string `json:"protocol"`
		TargetIp string `json:"targetIp"`
	} `json:"crawling"`

	//Sphere   string `json:"sphere"`   // sphjere ip&ip ..
	//Station  string `json:"station"`  // station ip&ip ..
}

// from sphere, idle to agent
type notiFirewall struct {
	UuID    string `json:"uuid"`
	DevID   int    `json:"devid"`
	Source  string `json:"source"`  // sphere, idle
	Command int    `json:"command"` // 0:insert, 1:delete
	List    int    `json:"list"`    // 0:white list, 1:black list
	Reason  string `json:"reason"`
	Buff    string `json:"buff"`

	KeyList []struct {
		Ip     string `json:"ip"`
		Port   int    `json:"port"`
		Period int    `json:"period"`
	} `json:"keyList"`
}

// idle, firewall 의해 black list에 insert 될때 sphere에게 보고
// send  -> if it did not receive 200 ok, try again
// to sphere
type reportfirewall struct {
	UuID    string `json:"uuid"`
	Command int    `json:"command"` // 0:insert, 1:delete
	List    int    `json:"list"`    // 0:white list, 1:black list
	Source  string `json:"source"`  // firewall, idle
	Time    uint32 `json:"time"`    // connect time
	Ip      string `json:"ip"`      // bad client ip
	Port    int    `json:"port"`    // service port
	Period  uint32 `json:"period"`  // 0:무제한, n: 초
	Reason  string `json:"reason"`  // flood, slow read, service port
	Service string `json:"service"` // 접속 service
	Buff    string `json:"buff"`    // ips, webfillter packet
}

// to sphere
type SetPlusAttackReportOneParam struct {
	ClientIp     string `json:"clientIp"`
	Uuid         string `json:"uuid"`
	Fqdn         string `json:"fqdn"`
	ReportReason string `json:"reportReason"`
}

// to spehre
type fqdnProvider struct {
	Fqdn string `json:"fqdn"`
}

// get sphere
type fqdnProviderResponse struct {
	Host          string `json:"host"`
	Domain        string `json:"domain"`
	ProviderIndex string `json:"providerIndex"`
	ProviderName  string `json:"providerName"`
	UserIndex     string `json:"userIndex"`
	CacheYN       string `json:"cacheYN"`
	ClientYN      string `json:"clientYN"`
	DomainYN      string `json:"domainYN"`
}

func makeReqJson() []byte {

	var req request

	// device info
	req.UuID = Agent_t.uuId
	req.Os = Agent_t.osName
	req.OsBit = Agent_t.osBit
	//req.Uptime = uint32(time.Since(Agent_t.upTime))
	req.IspInfo = Agent_t.ispResult

	// sys state
	req.SysState_t.Cpu = Agent_t.sysState_t.cpu
	req.SysState_t.Mem = Agent_t.sysState_t.mem
	req.SysState_t.Net = Agent_t.sysState_t.net
	req.SysState_t.Disk = Agent_t.sysState_t.disk
	//req.SysState_t.LOADAVG = Agent_t.sysState_t.loadAvg

	// cache info
	for _, d := range Agent_t.cache_t {

		var cd Cache_s
		cd.Domain = d.domain

		// host에 대한 cache가 없을 경우 미 보고
		if len(d.hostInfo_t) == 0 {
			continue
		}

		for _, h := range d.hostInfo_t {
			var ch HostInfo_s
			ch.Host = h.host
			ch.CacheSize = h.cacheSize

			cd.HostInfo_t = append(cd.HostInfo_t, ch)
		}

		req.Cache_t = append(req.Cache_t, cd)
	}

	// nic info
	for i := 0; i < len(Agent_t.nic_t); i++ {
		var NicState_t NicState_s
		an := Agent_t.nic_t[i]

		NicState_t.NicName = an.nicName
		NicState_t.NicUse = an.nicUse
		NicState_t.NicLink = an.nicLink
		NicState_t.NicAdmin = an.nicAdmin
		NicState_t.NicMac = an.nicMac
		NicState_t.NicIpv = an.nicIpv
		NicState_t.NicIP = an.nicIp
		NicState_t.NicPubIP = an.nicPubIp

		// plg info
		for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
			var PlgState_t PlgState_s
			anp := an.plugin_t[j]

			PlgState_t.PlgID = anp.plgId
			PlgState_t.PlgVer = anp.plgVer
			PlgState_t.ProID = anp.proId
			PlgState_t.ProVer = anp.proVer
			PlgState_t.PlgName = anp.plgName
			PlgState_t.PlgState = anp.plgNowState

			NicState_t.Plugin_t = append(NicState_t.Plugin_t, PlgState_t)
		}

		req.NicState_t = append(req.NicState_t, NicState_t)
	}

	// cert info
	for i := 0; i < len(Agent_t.cert_t); i++ {
		var CertState_t CertState_s
		ac := Agent_t.cert_t[i]

		CertState_t.CertId = ac.certId
		//CertState_t.CertVer = ac.certVer

		req.CertState_t = append(req.CertState_t, CertState_t)
	}

	jsonBytes, err := json.Marshal(req)
	if err != nil {
		lprintf(1, "[ERROR] json marshal fail(%s)", err.Error())
		return nil
	}

	lprintf(4, "[INFO] json marshal data (%s)\n", string(jsonBytes))

	return jsonBytes
}

func parseJson(data []byte) (int, response) {

	var response_t response

	err := json.Unmarshal(data, &response_t)
	if err != nil {
		lprintf(1, "[ERROR] json ummarsahl error(%s) \n", err.Error())
		return FAIL, response_t
	}

	return SUCCESS, response_t
}

func parseNoti(data []byte) (int, notify) {

	var notify_t notify

	err := json.Unmarshal(data, &notify_t)
	if err != nil {
		lprintf(1, "[ERROR] json ummarsahl error(%s) \n", err.Error())
		return FAIL, notify_t
	}

	return SUCCESS, notify_t
}

func parseNotifire(data []byte) (int, notiFirewall) {

	var notifire_t notiFirewall

	err := json.Unmarshal(data, &notifire_t)
	if err != nil {
		lprintf(1, "[ERROR] json ummarsahl error(%s) \n", err.Error())
		return FAIL, notifire_t
	}

	return SUCCESS, notifire_t
}

func parseProvider(data []byte) (int, fqdnProviderResponse) {

	var fp fqdnProviderResponse

	err := json.Unmarshal(data, &fp)
	if err != nil {
		lprintf(1, "[ERROR] json(%s) ummarsahl error(%s) \n", string(data), err.Error())
		return FAIL, fp
	}

	return SUCCESS, fp
}
