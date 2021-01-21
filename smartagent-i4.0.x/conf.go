/*
	smartagent config setting (init)
*/
package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"charlie/i0.0.2/cls"
)

// active code
const (
	NO = iota
	YES
)

// return code
const (
	FAIL    = -1
	SUCCESS = 1
)

// operation info
const (
	OP_PLGINSTALL = iota
	OP_PLGUPDATE
	OP_PLGDELETE
	OP_PROUPDATE
	OP_RESTART
	OP_INIT
)

// plugin notify info
const (
	PN_REGION = iota // region server ip (db, sphere, station)
	PN_DOMAIN        // idle use domain name
)

// sphere notify info
const (
	NT_AGENT       = iota // notify agent report send
	NT_FIREWALL           // notify make ctl file
	NT_IDLE               // notify make ctl file
	NT_ALIVE              // notify check devid
	NT_MANAGER            // notify manager (sphere use)
	NT_SITE               // notify site (sphere use)
	NT_DEFVER             // notify defrull Change (sphere use)
	NT_CACHE              // notify cache dir delete
	NT_SETCRAWLING        // notify set crawling
	NT_DELCRAWLING        // notify del crawling
)

// sphere notify response code
const (
	NT_SUCCESS string = "200" // notify success
	NT_BADREQ  string = "400" // notify req body read fail, json parsing fail
	NT_NOTDEV  string = "404" // notify response device id != agent deivce id
	NT_FAIL    string = "500" // notify do fail
)

// station file download info
const (
	ST_PLUGIN  = iota // smartstation plugin down
	ST_PROFILE        // smartstation profile down
	ST_CERT           // smartstation cert down
	ST_KEY            // smartstation key down
)

// agent path info
const DEFAULT_PATH string = "/smartagent/Plugins/"                        // default path
const DEFAULT_NIC string = "DFA"                                          // default nic name
const SMARTAGENT_PATH string = DEFAULT_PATH + DEFAULT_NIC + "/smartagent" // smartagent binary path
const SMARTAGENT_TMP string = SMARTAGENT_PATH + "/tmp"                    // smartagent tmp path
const SMARTAGENT_BAK string = SMARTAGENT_PATH + "/bak"                    // smartagent bak path
const SMARTAGENT_CERT string = SMARTAGENT_PATH + "/cert"                  // smartagent cert path
const SMARTAGENT_CONF string = SMARTAGENT_PATH + "/conf"                  // smartagent conf path
const PLUGIN_START string = "/op-shell/start.sh"                          // plugin start path
const PLUGIN_STOP string = "/op-shell/stop.sh"                            // plugin stop path

//const SMARTAGENT_TAR string = SMARTAGENT_PATH + "/tar_update.sh"          // smartagent self tar update path
//const SMARTAGENT_CFG string = SMARTAGENT_PATH + "/cfg_update.sh"          // smartagent self cfg update path
//const PLUGIN_INSTALL string = "/op-shell/install.sh"     // plugin install path
//const PLUGIN_UNINSTALL string = "/op-shell/uninstall.sh" // plugin uninstall path

var FqdnMap = struct {
	sync.RWMutex
	m map[string]Provider
}{m: make(map[string]Provider)}

type Provider struct {
	Host          string
	Domain        string
	ProviderIndex string
	ProviderName  string
	UserIndex     string
	CacheYN       string
	ClientYN      string
	DomainYN      string

	InTime int // ttl
}

type Agent_s struct {
	uuId       string // uuid gen
	osName     string // os name
	osBit      string // os bit
	deviceName string
	//upTime time.Time

	ispinfo_t  []ispinfo_s
	ispResult  string
	ispTimeOut int

	sysState_t sysState_s
	cache_t    []cache_s

	// body nic info
	nic_t []nic_s

	cert_t []cert_s

	plgId  string // smartagent plugin id
	plgVer int    // smartagent plugin ver
	proId  string // smartagent profile id
	proVer int    // smartagent profile ver

	reportInterval int // report interval sec
	//slack    string // slack url
	fromMail  string // plugin state send mail
	toMail    string // plugin state receive mail
	getIp     string // "http://what-is-myip.net"
	cacheDir  string // cache dir
	agentPort string

	// firewall info : tskim
	fireVer int // firewall rule version
	defVer  int // defence rule version (flooding, slow read)
	defUse  int // defence deteckt use

	// target server info
	rsphere     string // region smartsphere ip
	rsphereUUID string // region smartsphere uuid
	rstation    string // region smartstation ip
	rdb         string // region db ip
	rcl         string // region crawling ip

	mfluentd string // main fluentd ip

	mD  string // mongo db database
	mC  string // mongo db collection
	mH  string // mongo db host
	mP  string // mongo db port
	mU  string // mongo db user
	mPW string // mongo db password
	mT  int    // mongo db flag

	// stat info
	freeNet  uint64
	freeTime int64
	newNet   uint64
	newTime  int64
}

type nic_s struct {

	// nic base info
	nicName  string // nic card name
	nicMac   string // nic card use flag
	nicIpv   int    // nic card ip version (4, 6)
	nicIp    string // nic private ip
	nicPubIp string // nic public ip

	// nic state info
	nicAdmin int // system allocated the resources for to interface (1: up, 0: down)
	nicLink  int // ethernet cables is really connected to network (1: up, 0: down)
	nicUse   int // nic 사용여부

	plugin_t []plugin_s
}

type cert_s struct {
	certId  string
	certVer int
}

type plugin_s struct {

	// nic base info
	nicName string

	// plugin base info
	plgName string
	plgId   string // plugin Id
	plgVer  int    // plugin ver
	proId   string
	proVer  int

	pId         int // pid
	plgState    int // plugin state (recive Server)
	plgNowState int // plugin now state (real time)

}

type ispinfo_s struct {
	domain string // www.kt.com
	alias  string // kt
	state  string // on, off
	stated string // 이전 on, off
}

type sysState_s struct {
	cpu  string // cpu usage			ex) 32.1 %
	mem  string // memory usage  		ex) 60.3%
	swap string // swap memory usage  	ex) 40.44%
	disk string // disk usage           ex) 60%
	net  uint64 // net usage			mbps/sec

	/*
		Gbps : Gigabit per second (Gbit/s or Gb/s)
		Mbps : Megabit per second (Mbit/s or Mb/s)
		prefix mega : 10002
		prefix giga : 10003
		1 megabit = 10002 bits
		1 gigabit  = 10003 bits
		1 gigabit  = 10003-2 megabits
		1 gigabit  = 1000 megabits
		1 gigabit/second = 1000 megabits/second
		1 Gbps = 1000 Mbps
	*/

	tcp     int // tcp session count
	loadAvg int // uptime load average 1 min
}

type cache_s struct {
	domain     string
	hostInfo_t []hostInfo_s
}

type hostInfo_s struct {
	host      string
	cacheSize string
}

func App_conf(fname string) int {

	lprintf(4, "[INFO] smartagent App_conf start(%s)\n", cls.ConfDir)

	var value int
	var err error

	// conf/smartagent.ini read
	v, r := cls.GetTokenValue("REPORT_INTERVAL_SEC", fname)
	if r != cls.CONF_ERR {
		value, err = strconv.Atoi(v)
		if err != nil {
			lprintf(1, "[ERROR] REPORT_INTERVAL_SEC value error(%s), set 30sec \n", v)
			Agent_t.reportInterval = 30
		}

		Agent_t.reportInterval = value

	} else {
		lprintf(4, "[INFO] REPORT_INTERVAL_SEC not found set 30 \n")
		Agent_t.reportInterval = 30
	}

	v, r = cls.GetTokenValue("GETMYIP", fname)
	if r != cls.CONF_ERR {
		Agent_t.getIp = v
	} else {
		Agent_t.getIp = "what-is-myip.org&what-is-myip.net"
	}

	v, r = cls.GetTokenValue("CONNECT_TIMEOUT", fname)
	if r != cls.CONF_ERR {
		value, err = strconv.Atoi(v)
		if err != nil {
			lprintf(1, "[ERROR] CONNECT_TIMEOUT value error(%s), set 3sec \n", v)
			Agent_t.ispTimeOut = 3
		}

		Agent_t.ispTimeOut = value
	} else {
		Agent_t.ispTimeOut = 3
	}

	v, r = cls.GetTokenValue("STAT_SERVER", fname)
	if r != cls.CONF_ERR {
		Agent_t.rstation = v
	}

	v, r = cls.GetTokenValue("WEB_PORT", fname)
	if r != cls.CONF_ERR {
		Agent_t.agentPort = v
	} else {
		Agent_t.agentPort = "1063"
	}

	v, r = cls.GetTokenValue("CACHEDIR", fname)
	if r != cls.CONF_ERR {
		Agent_t.cacheDir = v
	} else {
		Agent_t.cacheDir = "/tmp/cache"
	}

	lprintf(4, "[INFO] cahce dir(%s) \n", Agent_t.cacheDir)

	/*
		v, r = cls.GetTokenValue("SLACK", fname)
		if r != cls.CONF_ERR {
			Agent_t.slack = v
		} else {
			Agent_t.slack = "https://hooks.slack.com/services/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"
		}
	*/

	v, r = cls.GetTokenValue("FROM_MAIL", fname)
	if r != cls.CONF_ERR {
		Agent_t.fromMail = v

		v, r = cls.GetTokenValue("TO_MAIL", fname)
		if r != cls.CONF_ERR {
			Agent_t.toMail = v
		} else {
			lprintf(1, "[FAIL] TO_MAIL not found, not use send mail \n")
		}

	}

	v, r = cls.GetTokenValue("M_FLUENTD", fname)
	if r != cls.CONF_ERR {
		Agent_t.mfluentd = v
	}

	// station 신규 설치 시 해당 장비 fluentd config 관리를 위한 데이터
	v, r = cls.GetTokenValue("MONGO_HOST", fname)
	if r != cls.CONF_ERR {
		Agent_t.mH = v
	} else {
		Agent_t.mT = 1
	}

	v, r = cls.GetTokenValue("MONGO_PORT", fname)
	if r != cls.CONF_ERR {
		Agent_t.mP = v
	} else {
		Agent_t.mT = 1
	}

	v, r = cls.GetTokenValue("MONGO_ID", fname)
	if r != cls.CONF_ERR {
		Agent_t.mU = v
	} else {
		Agent_t.mT = 1
	}

	v, r = cls.GetTokenValue("MONGO_PWD", fname)
	if r != cls.CONF_ERR {
		Agent_t.mPW = v
	} else {
		Agent_t.mT = 1
	}

	v, r = cls.GetTokenValue("MONGO_DB", fname)
	if r != cls.CONF_ERR {
		Agent_t.mD = v
	} else {
		Agent_t.mT = 1
	}

	v, r = cls.GetTokenValue("MONGO_COLLECT", fname)
	if r != cls.CONF_ERR {
		Agent_t.mC = v
	}

	// isp set
	for i := 1; i < 11; i++ {
		var ispinfo_t ispinfo_s

		s := fmt.Sprintf("CONNECT_DOMAIN_%d", i)

		v, r = cls.GetTokenValue(s, fname)
		if r != cls.CONF_ERR {

			idx := strings.Index(v, ",")
			if idx < 0 {
				lprintf(1, "[ERROR] isp info is not correct, please change(url, alias) (%s)", v)
				continue
			}

			domain := strings.TrimSpace(v[:idx])

			if strings.Contains(domain, "http://") {
				lprintf(1, "[ERROR] isp info set http protocol(%s), please delete \n", domain)
				return FAIL
			} else {
				ispinfo_t.domain = domain
			}

			ispinfo_t.alias = strings.TrimSpace(v[idx+1:])

			Agent_t.ispinfo_t = append(Agent_t.ispinfo_t, ispinfo_t)

		} else {
			//lprintf(1, "[FAIL] connect domain not use(%s) \n", s)
			break
		}
	}

	// smartagent server info set (os name, bit)
	if setDeviceInfo() < 0 {
		lprintf(1, "[FAIL] smartagent os info error(%s) \n", runtime.GOOS)
		return FAIL
	}

	// smartagent network info (eth state)
	res, nic_t := setNetworkInfo()
	if res < 0 {
		lprintf(1, "[FAIL] smartagent network info error \n")
		return FAIL
	}

	for i := 0; i < len(nic_t); i++ {
		Agent_t.nic_t = append(Agent_t.nic_t, nic_t[i])
	}

	return SUCCESS

}

func setDeviceInfo() int {

	cmd := "uname"
	_, resp := RunCmd_S(cmd)
	// platform, bit
	if resp != "Linux" || resp != "linux" {
		Agent_t.osName = resp
	} else {
		Agent_t.osName = "Linux"
	}

	cmd = "uname -m"
	_, resp = RunCmd_S(cmd)

	if resp != "x86_64" {
		Agent_t.osBit = "32"
	} else {
		Agent_t.osBit = "64"
	}

	//Agent_t.upTime = time.Now()

	return SUCCESS

}

func setNetworkInfo() (int, []nic_s) {

	var nic_t []nic_s

	// get interfaces MAC/hardware address
	netInterfaces, err := net.Interfaces()
	if err != nil {
		lprintf(1, "[ERROR] get net interface error(%s)\n", err.Error())
		return FAIL, nic_t
	}

	// DFA nic setting
	var dfaNic nic_s
	dfaNic.nicName = DEFAULT_NIC
	dfaNic.nicUse = SUCCESS
	dfaNic.nicMac = fmt.Sprintf("%s", "00:00:00:00:00:00")
	dfaNic.nicIp = fmt.Sprintf("%s", "0.0.0.0")
	dfaNic.nicPubIp = fmt.Sprintf("%s", "0.0.0.0")
	dfaNic.nicIpv = 0
	dfaNic.nicAdmin = NO
	dfaNic.nicLink = NO

	nic_t = append(nic_t, dfaNic)

	// real interface setting
	for _, netInter := range netInterfaces {

		lprintf(4, "[INFO] netInter.Name : %s \n", netInter.Name)

		if netInter.Name == "lo" {
			continue
		}

		var nic nic_s
		nic.nicName = netInter.Name
		nic.nicUse = SUCCESS

		// set mac addr
		nic.nicMac = netInter.HardwareAddr.String()
		if len(nic.nicMac) == 0 {
			nic.nicMac = fmt.Sprintf("%s", "00:00:00:00:00:00")
			lprintf(1, "[FAIL] %s get mac addr fail \n", nic.nicName)
		}

		// set private ip, public ip
		netAddr, err := netInter.Addrs()
		if err != nil {
			lprintf(1, "[ERROR] list interface address error(%s)\n", err.Error())
			continue
		}

		for _, addr := range netAddr {
			ip := addr.String()
			lprintf(4, "[INFO] get addr (%s)\n", ip)

			if ip == "127.0.0.1" {
				continue
			}

			if strings.ContainsAny(ip, ".") {
				nic.nicIpv = 4
			} else {
				//nic.nicIpv = 6
				continue
			}

			addrList := strings.Split(ip, "/")
			nic.nicIp = addrList[0]

			rst, getIp := getPublicIp(nic.nicIp)
			if rst > 0 {
				nic.nicPubIp = getIp
			}

		}

		lprintf(4, "[INFO] net nicLink(%s) \n", netInter.Flags.String())

		if strings.Contains(netInter.Flags.String(), "up") {
			nic.nicAdmin = YES
		}
		if !strings.Contains(netInter.Flags.String(), "loopback") {
			nic.nicLink = YES
		}

		nic_t = append(nic_t, nic)
	}

	return SUCCESS, nic_t
}

func getPublicIp(srcIp string) (int, string) {

	var serverIp, getIp string
	var rst int
	var host bool

	if Agent_t.getIp == "STATION" && len(Agent_t.rstation) > 0 {
		serverIp = Agent_t.rstation
		host = true
	} else {
		serverIp = Agent_t.getIp
	}

	targetIp := strings.Split(serverIp, "&")
	for i := 0; i < len(targetIp); i++ {
		ip := targetIp[(cls.SvrIdx+i)%len(targetIp)]
		rst, getIp = getPublic(ip, srcIp, host)
		if rst > 0 {
			return SUCCESS, getIp
		}
	}

	return FAIL, getIp

}

func getPublic(httpFqdn, srcIp string, host bool) (int, string) {

	var getIp string

	localAddr, err := net.ResolveIPAddr("ip", srcIp)
	if err != nil {
		lprintf(1, "[ERROR] ResolveIPAddr(%s) err(%s) \n", srcIp, err.Error())
		return FAIL, getIp
	}

	localTCPAddr := net.TCPAddr{
		IP: localAddr.IP,
	}

	var netTransport = &http.Transport{
		DialContext: (&net.Dialer{
			LocalAddr: &localTCPAddr,
			Timeout:   3 * time.Second,
			KeepAlive: 3 * time.Second,
			//DualStack: true,
		}).DialContext,
	}
	defer netTransport.CloseIdleConnections()
	//netTransport.MaxIdleConns

	client := &http.Client{
		Timeout:   time.Second * 3,
		Transport: netTransport,
	}

	if !strings.Contains(httpFqdn, "http://") {
		httpFqdn = "http://" + httpFqdn
	}

	lprintf(4, "[INFO] get public ip fqdn(%s) \n", httpFqdn)

	// get public ip
	req, err := http.NewRequest("GET", httpFqdn, nil)
	if err != nil {
		lprintf(1, "[ERROR] http new request err(%s) \n", err.Error())
		return FAIL, getIp
	}

	if host {
		req.Host = "what-is-myip"
	}

	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		lprintf(1, "[ERROR] client do err(%s) \n", err.Error())
		return FAIL, getIp
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lprintf(1, "[ERROR] response body read err(%s) \n", err.Error())
		return FAIL, getIp
	}
	resp.Body.Close()

	if strings.Contains(string(data), "<body>") {
		htmlParse := strings.Split(string(data), "<body>")
		publicIp := strings.Split(htmlParse[1], "</body>")
		getIp = strings.TrimSpace(publicIp[0])
	} else {
		getIp = strings.TrimSpace(string(data))
	}

	lprintf(4, "[INFO] get public ip(%s) \n", getIp)

	return SUCCESS, getIp

}

func setAgentPlg(fname string) (int, plugin_s) {

	var plgInfo plugin_s

	v, r := cls.GetTokenValue("PLUGIN_ID", fname)
	if r != cls.CONF_ERR {
		Agent_t.plgId = v
	} else {
		lprintf(1, "[FAIL] PLUGIN_ID not found (%s)\n", fname)
		return FAIL, plgInfo
	}

	v, r = cls.GetTokenValue("PLUGIN_VER", fname)
	if r != cls.CONF_ERR {
		Agent_t.plgVer, _ = strconv.Atoi(v)
	} else {
		lprintf(1, "[FAIL] PLUGIN_VER not found (%s)\n", fname)
		return FAIL, plgInfo
	}

	v, r = cls.GetTokenValue("PROFILE_ID", fname)
	if r != cls.CONF_ERR {
		Agent_t.proId = v
	} else {
		lprintf(1, "[FAIL] PROFILE_ID not found (%s)\n", fname)
		return FAIL, plgInfo
	}

	v, r = cls.GetTokenValue("PROFILE_VER", fname)
	if r != cls.CONF_ERR {
		Agent_t.proVer, _ = strconv.Atoi(v)
	} else {
		lprintf(1, "[FAIL] PROFILE_VER not found (%s)\n", fname)
		return FAIL, plgInfo
	}

	// set plugin info

	v, r = cls.GetTokenValue("SERVER_NAME", fname)
	if r != cls.CONF_ERR {
		plgInfo.plgName = v
	} else {
		return SUCCESS, plgInfo
	}

	v, r = cls.GetTokenValue("SERVER_PLGID", fname)
	if r != cls.CONF_ERR {
		plgInfo.plgId = v
	} else {
		lprintf(1, "[FAIL] SERVER_PLGID not found (%s)\n", fname)
		plgInfo.plgName = ""
	}

	v, r = cls.GetTokenValue("SERVER_PLGVER", fname)
	if r != cls.CONF_ERR {
		plgInfo.plgVer, _ = strconv.Atoi(v)
	} else {
		lprintf(1, "[FAIL] SERVER_PLGVER not found (%s)\n", fname)
		plgInfo.plgName = ""
	}

	v, r = cls.GetTokenValue("SERVER_PROID", fname)
	if r != cls.CONF_ERR {
		plgInfo.proId = v
	} else {
		lprintf(1, "[FAIL] SERVER_PROID not found (%s)\n", fname)
		plgInfo.plgName = ""
	}

	v, r = cls.GetTokenValue("SERVER_PROVER", fname)
	if r != cls.CONF_ERR {
		plgInfo.proVer, _ = strconv.Atoi(v)
	} else {
		lprintf(1, "[FAIL] SERVER_PROVER not found (%s)\n", fname)
		plgInfo.plgName = ""
	}

	return SUCCESS, plgInfo
}
