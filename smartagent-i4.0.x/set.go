/*
	smartagent set data
	net interface state check
	plugin state check
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"charlie/i0.0.2/cls"

	"github.com/julienschmidt/httprouter"
)

var ClientInfo = struct {
	sync.RWMutex
	m map[string]int // key - clientIp
}{m: make(map[string]int)} // value - intime sec

// 주기적으로 장비 상태를 체크
// ddos 공격 판단 시 다음 노드 할당을 위해 장비 shut down
func devStateCheck() {

	flag := false

	for {
		time.Sleep(60 * time.Second)

		/*
			// cpu 90% 체크
			if len(Agent_t.sysState_t.cpu) < 2 && Agent_t.sysState_t.cpu[0] != '9' {
				continue
			}

			// bandwith 1GB 중 90% 체크
			if Agent_t.sysState_t.net < 90 {
				continue
			}

			lprintf(1, "[ERROR] SYSTEM SHUT DOWN CPU(%s), NET(%d) \n", Agent_t.sysState_t.cpu, Agent_t.sysState_t.net)

			for i := 0; i < len(Agent_t.nic_t); i++ {
				for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
					if Agent_t.nic_t[i].plugin_t[j].plgName == "smartidle" {
						PlgStop(Agent_t.nic_t[i].plugin_t[j])
					}
				}
			}
		*/

		rst, socketCnt := RunCmd_S("netstat -np | grep tcp | wc -l")
		if rst < 0 {
			continue
		}

		sc, err := strconv.Atoi(socketCnt)
		if err != nil {
			lprintf(1, "[ERROR] socketCnt(%s) atoi err(%s) \n", socketCnt, err.Error())
			continue
		}

		if sc >= 1000 {
			if flag {
				lprintf(1, "[ERROR] system shutdown CPU(%s), NET(%d), NETSTAT(%d) \n", Agent_t.sysState_t.cpu, Agent_t.sysState_t.net, sc)
				RunCmd_N("> /etc/crontab")
				os.Exit(0)
			} else {
				lprintf(1, "[ERROR] system danger CPU(%s), NET(%d), NETSTAT(%d) \n", Agent_t.sysState_t.cpu, Agent_t.sysState_t.net, sc)
				flag = true
			}
		} else {
			flag = false
		}
	}

}

func netStateCheck() int {

	updateFlag := NO
	var deleteNic string

	//make new nic interface
	lprintf(4, "[INFO] setNetworkInfo start \n")
	resp, newNic := setNetworkInfo()

	if resp < 0 {
		lprintf(1, "[ERROR] netStateCheck make new nic fail \n")
		return FAIL
	}

	// old nic check update and delete
	for i := 1; i < len(Agent_t.nic_t); i++ {
		for j := 1; j < len(newNic); j++ {
			if Agent_t.nic_t[i].nicName == newNic[j].nicName {

				// update old nic
				Agent_t.nic_t[i].nicLink = newNic[j].nicLink
				Agent_t.nic_t[i].nicAdmin = newNic[j].nicAdmin
				Agent_t.nic_t[i].nicIp = newNic[j].nicIp
				Agent_t.nic_t[i].nicIpv = newNic[j].nicIpv
				if len(newNic[j].nicPubIp) > 0 {
					Agent_t.nic_t[i].nicPubIp = newNic[j].nicPubIp
				}
				Agent_t.nic_t[i].nicMac = newNic[j].nicMac

				updateFlag = YES
				break
			}
		}

		if updateFlag != YES {
			// delete old nic
			lprintf(4, "[INFO] device net interface change, nic delete(%s)\n", Agent_t.nic_t[i].nicName)
			//Agent_t.nic_t = append(Agent_t.nic_t[:i], Agent_t.nic_t[i+1:])
			deleteNic = Agent_t.nic_t[i].nicName
			Agent_t.nic_t = Agent_t.nic_t[:i+copy(Agent_t.nic_t[i:], Agent_t.nic_t[i+1:])]
		}

		updateFlag = NO
	}
	updateFlag = YES

	// new nic inseart
	for i := 1; i < len(newNic); i++ {
		for j := 1; j < len(Agent_t.nic_t); j++ {

			if newNic[i].nicName == Agent_t.nic_t[j].nicName {
				updateFlag = NO
				break
			}
		}

		if updateFlag == YES {
			// inseart new nic
			lprintf(4, "[INFO] device net interface change, nic inseart(%s)\n", newNic[i].nicName)
			Agent_t.nic_t = append(Agent_t.nic_t, newNic[i])
		}

		updateFlag = YES
	}

	if len(deleteNic) > 0 {
		lprintf(4, "[INFO] sql delete nic \n")

		var plugin_sql_t plugin_sql
		plugin_sql_t.PluginName = deleteNic

		if SqlDeletePlugin(plugin_sql_t) < 0 {
			lprintf(1, "[ERROR] sql delete nic fail \n")
			return FAIL
		}

	}

	return SUCCESS
}

func sysStateCheck() int {

	ispStateCheck()
	if FindPlgName("nginx") {
		cacheStateCheck()
	}

	var resp int
	var respStr, cmd string

	//cmd = "top -b -n2 -p 1 | fgrep \"Cpu(s)\" | tail -1 | awk -F'id,' -v prefix=\"$prefix\" '{ split($1, vs, \", \"); v=vs[length(vs)]; sub(\"%\", \"\", v); printf \"%s%.f%\", prefix, 100 - v }'"
	//resp, respStr = RunCmd_S(cmd)
	//if len(respStr) == 0 {
	cmd = "top -b -n1 | grep -Po '[0-9.]+ id' | awk '{print 100-$1}'"
	_, respStr = RunCmd_S(cmd)
	//}

	if len(respStr) == 0 {
		cmd = "top -b -n2 -p 1 | fgrep \"Cpu(s)\" | tail -1 | awk -F'id,' -v prefix=\"$prefix\" '{ split($1, vs, \", \"); v=vs[length(vs)]; sub(\"%\", \"\", v); printf \"%s%.f%\", prefix, 100 - v }'"
		_, respStr = RunCmd_S(cmd)
	}

	if len(respStr) > 0 {

		if strings.Contains(respStr, "%") {
			Agent_t.sysState_t.cpu = respStr[:len(respStr)-1]
		} else {
			Agent_t.sysState_t.cpu = respStr
		}

		lprintf(4, "[INFO] cpu usage = %s\n", Agent_t.sysState_t.cpu)
	} else {
		lprintf(4, "[INFO] cpu get fail \n")
		Agent_t.sysState_t.cpu = "0"
	}

	cmd = "free | grep ^Mem | awk '{printf \"%s\",$3 / $2*100}'"
	resp, respStr = RunCmd_S(cmd)
	if resp < 0 {
		lprintf(1, "[ERROR] get mem fail, cmd(%s) \n", cmd)
	} else if len(respStr) > 0 {
		Agent_t.sysState_t.mem = respStr
		lprintf(4, "[INFO] mem = %s\n", respStr)
	}

	cmd = "free | grep '^Swap' | awk '{printf \"%s\",$3 / $2*100}'"
	resp, respStr = RunCmd_S2(cmd)
	if resp > 0 && len(respStr) > 0 {
		Agent_t.sysState_t.swap = respStr
		lprintf(4, "[INFO] swap = %s\n", respStr)
	}

	cmd = "df / -h -P | awk 'NR >=2 {print $5}'"
	resp, respStr = RunCmd_S(cmd)
	if resp < 0 {
		lprintf(1, "[ERROR] get disk fail, cmd(%s) \n", cmd)
	} else if len(respStr) > 0 {
		Agent_t.sysState_t.disk = respStr[:len(respStr)-1]
		lprintf(4, "[INFO] disk usage = %s\n", respStr)
	}

	if len(Agent_t.nic_t) > 1 {
		cmd = "grep " + Agent_t.nic_t[1].nicName + " /proc/net/dev | awk '{print $2}'"
	} else {
		cmd = "grep eth0 /proc/net/dev | awk '{print $2}'"
	}

	resp, respStr = RunCmd_S(cmd)
	if resp < 0 {
		lprintf(1, "[ERROR] get bandwith fail, cmd(%s) \n", cmd)
	} else {
		lprintf(4, "[INFO] net1 = (%s)\n", respStr)
		net1, _ := strconv.ParseUint(respStr, 0, 64)

		Agent_t.freeNet = Agent_t.newNet
		Agent_t.newNet = net1

		newTime := time.Now().Unix()
		Agent_t.freeTime = Agent_t.newTime
		Agent_t.newTime = newTime

		// 1000000000 byte -> 1 GB

		if Agent_t.freeNet > 0 && Agent_t.newNet > 0 && Agent_t.newTime > Agent_t.freeTime {
			Agent_t.sysState_t.net = (Agent_t.newNet - Agent_t.freeNet) / uint64(Agent_t.newTime-Agent_t.freeTime) / 1000000000 * 100 // 1000000000 GB, 1000000 MB
			lprintf(4, "[INFO] bandwith use(%d-%d / %d / 1000000000 * 100) of 1GB/sec = (%d) \n", Agent_t.newNet, Agent_t.freeNet, Agent_t.newTime-Agent_t.freeTime, Agent_t.sysState_t.net)
		}
	}

	/*
		cmd = "netstat -na | grep ESTABLISHED | wc -l"
		resp, respStr = RunCmd_S(cmd)
		if resp < 0 {
			lprintf(1, "[ERROR] get tcp fail, cmd(%s) \n", cmd)
		} else {
			Agent_t.sysState_t.tcp, _ = strconv.Atoi(respStr)
		}

		lprintf(4, "[INFO] tcp session count = (%d) \n", Agent_t.sysState_t.tcp)

		cmd = "uptime"
		resp, respStr = RunCmd_S(cmd)
		if resp < 0 {
			lprintf(1, "[ERROR] get uptime, cmd(%s) \n", cmd)
		} else {
			temp := strings.Split(respStr, "average:")
			if len(temp) > 1 {
				temp = strings.Split(temp[1], ",")
				temp = strings.Split(temp[0], ".")
				Agent_t.sysState_t.loadAvg, _ = strconv.Atoi(strings.TrimSpace(temp[0]))

				lprintf(4, "[INFO] load avg 1min = (%d) \n", Agent_t.sysState_t.loadAvg)
			} else {
				lprintf(1, "[FAIL] get uptime fail, load avg(%s) \n", respStr)
			}
		}
	*/

	nowTime := time.Now()
	utc := nowTime.UTC().Format("2006-01-02 15:04:05")
	loc, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		lprintf(1, "[ERROR] time LoadLocation err(%s) \n", err.Error())
		return SUCCESS
	}

	kst := nowTime.In(loc).Format("2006-01-02 15:04:05")

	data := fmt.Sprintf("smartagent,%s,%s,%s,%s,%s,%d,%s,%s,%s", Agent_t.deviceName, Agent_t.sysState_t.cpu, Agent_t.sysState_t.mem, Agent_t.sysState_t.swap, Agent_t.sysState_t.disk, Agent_t.sysState_t.net, Agent_t.nic_t[1].nicPubIp, utc, kst)
	//cls.SetDeviceId(Agent_t.deviceId)
	cls.Lprints(1, data)

	return SUCCESS
}

func cacheStateCheck() {

	var cmd, cPath, dPath, hPath string
	var cache_t []cache_s

	for i := 1; i < len(Agent_t.nic_t); i++ {

		cPath = Agent_t.cacheDir + "/" + Agent_t.nic_t[i].nicName

		lprintf(4, "[INFO] cache dir(%s) read \n", cPath)

		files, err := ioutil.ReadDir(cPath)
		if err != nil {
			//lprintf(1, "[ERROR] cache dir read err(%s) \n", err.Error())
			continue
		}

		for _, domain := range files {
			if domain.IsDir() {

				var dc cache_s
				dc.domain = domain.Name()

				dPath = cPath + "/" + domain.Name()
				lprintf(4, "[INFO] cache dir domain(%s) \n", dPath)

				hosts, err := ioutil.ReadDir(dPath)
				if err != nil {
					lprintf(4, "[ERROR] cache dir read err(%s) \n", err.Error())
					continue
				}

				for _, host := range hosts {
					hPath = dPath + "/" + host.Name()

					cmd = fmt.Sprintf("du -bs %s | awk '{print $1}'", hPath)
					rst, size := RunCmd_S(cmd)
					if rst < 0 {
						continue
					}

					var hc hostInfo_s
					hc.host = host.Name()
					hc.cacheSize = size

					lprintf(4, "[INFO] cache dir(%s) host(%s), size(%s) \n", hPath, hc.host, hc.cacheSize)

					dc.hostInfo_t = append(dc.hostInfo_t, hc)
				}

				cache_t = append(cache_t, dc)
			}
		}
	}

	Agent_t.cache_t = cache_t

}

func ispStateCheck() {

	var ispInfo string

	// server listen state check
	for i := 0; i < len(Agent_t.ispinfo_t); i++ {

		Agent_t.ispinfo_t[i].stated = Agent_t.ispinfo_t[i].state

		d := net.Dialer{
			Timeout: time.Duration(Agent_t.ispTimeOut) * time.Second,
		}
		//	Dial("tcp", "golang.org:http")
		con, err := d.Dial("tcp", Agent_t.ispinfo_t[i].domain+":http")
		if err != nil {
			lprintf(1, "[ERROR] isp(%s) net dial fail(%s) \n", Agent_t.ispinfo_t[i].domain, err.Error())
			Agent_t.ispinfo_t[i].state = "off"
			con = nil
		} else {
			Agent_t.ispinfo_t[i].state = "on"
			con.Close()
		}
		//defer con.Close()

		ispInfo += Agent_t.ispinfo_t[i].alias + ":" + Agent_t.ispinfo_t[i].state + "/"

		lprintf(4, "[INFO] isp info domain(%s), state(%s) \n", Agent_t.ispinfo_t[i].domain, Agent_t.ispinfo_t[i].state)
	}

	if len(ispInfo) > 0 {
		Agent_t.ispResult = ispInfo[:len(ispInfo)-1]
	}

}

func plgStateCheck() int {

	var eth, plgName, pidList string
	var nicIndex int
	var fwNicIndex int
	fwPlgIndex := -1
	dbIndex := -1
	var pflag int

	// plg state check
	cmd := "pgrep -fl smart" // dev
	_, pidList1 := RunCmd_S2(cmd)

	cmd = "pgrep -afl smart" // aws
	_, pidList2 := RunCmd_S2(cmd)

	if len(pidList1) >= len(pidList2) {
		pidList = pidList1
	} else if len(pidList2) > len(pidList1) {
		pidList = pidList2
	}

	// plg now state reset
	for i := 0; i < len(Agent_t.nic_t); i++ {
		for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {

			if Agent_t.nic_t[i].plugin_t[j].plgName == "smartagent" {
				continue
			} else if Agent_t.nic_t[i].plugin_t[j].plgName == "smartfw" {
				fwNicIndex = i
				fwPlgIndex = j
			} else if Agent_t.nic_t[i].plugin_t[j].plgName == "db" {
				dbIndex = j
			}

			Agent_t.nic_t[i].plugin_t[j].plgNowState = NO
			Agent_t.nic_t[i].plugin_t[j].pId = 0
		}
	}

	// plg now state set
	lines := strings.Split(string(pidList), "\n")
	for _, value := range lines {

		psInfo := strings.Split(value, "/")
		lprintf(4, "[INFO] pid list line(%s) \n", value)

		if len(psInfo) < 10 || DEFAULT_PATH != "/"+psInfo[1]+"/"+psInfo[2]+"/" {
			lprintf(4, "[INFO] this line not pid list(%s) \n", value)
			continue
		}

		eth = psInfo[3]     // up eth
		plgName = psInfo[4] // up plugin name

		if plgName == "smartagent" {
			continue
		} else if plgName == "nginx" {
			nInfo := strings.Split(psInfo[0], " ") // 54213 nginx: master process
			if nInfo[2] == "master" {
				psInfo[0] = nInfo[0]
			}
		}

		for i := 0; i < len(Agent_t.nic_t); i++ {
			if Agent_t.nic_t[i].nicName == eth {
				nicIndex = i
				break
			}
		}

		for j := 0; j < len(Agent_t.nic_t[nicIndex].plugin_t); j++ {
			if Agent_t.nic_t[nicIndex].plugin_t[j].plgName == plgName {
				Agent_t.nic_t[nicIndex].plugin_t[j].plgNowState = YES
				Agent_t.nic_t[nicIndex].plugin_t[j].pId, _ = strconv.Atoi(strings.TrimSpace(psInfo[0]))
				lprintf(4, "[INFO] plugin(%s) now state up, pid(%d) \n", psInfo[4], Agent_t.nic_t[nicIndex].plugin_t[j].pId)
				break
			}
		}
	}

	//smartfw 체크
	if fwPlgIndex >= 0 {
		cmd = "lsmod | grep smartfw"
		_, fw := RunCmd_S(cmd)
		lprintf(4, "[INFO] smartfw state(%s) \n", fw)
		if len(fw) > 0 {
			Agent_t.nic_t[fwNicIndex].plugin_t[fwPlgIndex].plgNowState = YES
		}
	}

	if dbIndex >= 0 {
		cmd = "service mysql status" // centos 6
		rst, dbStatus := RunCmd_S2(cmd)
		if rst < 0 {
			cmd = "service mariadb status" // centos 7
			_, dbStatus = RunCmd_S(cmd)
		}

		if strings.Contains(dbStatus, "running") {
			Agent_t.nic_t[0].plugin_t[dbIndex].plgNowState = YES
		}
	}

	// state = 1 && nowState =0 start up and mail 발송
	for i := 0; i < len(Agent_t.nic_t); i++ {
		for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
			if Agent_t.nic_t[i].plugin_t[j].plgNowState == NO && Agent_t.nic_t[i].plugin_t[j].plgState == YES {

				// plugin info send mail
				lprintf(1, "[ERROR] nic(%s)-plugin(%s) down \n", Agent_t.nic_t[i].nicName, Agent_t.nic_t[i].plugin_t[j].plgName)
				SendMail(Agent_t.nic_t[i], Agent_t.nic_t[i].plugin_t[j])
				PlgStart(Agent_t.nic_t[i].plugin_t[j])
				pflag = -1

			}
		}
	}

	cmd = "pgrep -fl td-agent"
	_, tdList1 := RunCmd_S2(cmd)

	cmd = "pgrep -a td-agent"
	_, tdList2 := RunCmd_S2(cmd)

	if len(tdList1) == 0 && len(tdList2) == 0 && !FindPlgName("smartsphere") {
		cmd = "/etc/init.d/td-agent start"
		RunCmd_N(cmd)
	}

	if pflag < 0 {
		return FAIL
	}

	return SUCCESS
}

// do operation
func doOp(response_t response) int {

	var rst, notiUpdate int
	var cmd string
	var plugin_f, server_f plugin_s

	if len(response_t.UuID) > 0 && Agent_t.rsphereUUID != response_t.UuID {
		lprintf(4, "[INFO] get spherer uuid(%s) \n", response_t.UuID)
		Agent_t.rsphereUUID = response_t.UuID
	}

	if len(response_t.DeviceName) > 0 && Agent_t.deviceName != response_t.DeviceName {
		Agent_t.deviceName = response_t.DeviceName
	}

	// region target server update
	if len(response_t.RSphere) > 0 && Agent_t.rsphere != response_t.RSphere {

		lprintf(4, "[INFO] region sphere ip(%s) cls set \n", response_t.RSphere)
		cls.SetServerIp(cls.TCP_SPHERE, response_t.RSphere)

		Agent_t.rsphere = response_t.RSphere
		notiUpdate = 1
	}

	if len(response_t.RStation) > 0 && Agent_t.rstation != response_t.RStation {

		lprintf(4, "[INFO] region station ip(%s) cls set \n", response_t.RStation)
		cls.SetServerIp(cls.TCP_STATION, response_t.RStation)

		Agent_t.rstation = response_t.RStation
		setLogCollector()
		notiUpdate = 1
	}

	if len(response_t.RDb) > 0 && Agent_t.rdb != response_t.RDb {
		lprintf(4, "[INFO] region db ip(%s) change\n", response_t.RDb)
		Agent_t.rdb = response_t.RDb
		notiUpdate = 1
	}

	if len(response_t.RCrawl) > 0 && Agent_t.rcl != response_t.RCrawl {
		lprintf(4, "[INFO] region crawling ip(%s) change\n", response_t.RCrawl)
		Agent_t.rcl = response_t.RCrawl
		notiUpdate = 1
	}

	if notiUpdate > 0 {
		notiData := fmt.Sprintf("SPHERE=%s\nSTATION=%s\nDB=%s\nCRAWLER=%s", Agent_t.rsphere, Agent_t.rstation, Agent_t.rdb, Agent_t.rcl)
		go notiMakeFile("", "", notiData)
	}

	/*
		if Agent_t.defUse == 0 && response_t.DefUse == 1 {
			Agent_t.defUse = 1
		}
	*/

	if Agent_t.defUse != response_t.DefUse {
		Agent_t.defUse = response_t.DefUse
		lprintf(4, "[INFO] def use(%d) \n", response_t.DefUse)
	}

	// firewall update
	if Agent_t.fireVer != response_t.FireVer {
		lprintf(4, "[INFO] agent firewall version (%d), response firewall version (%d) different in op \n", Agent_t.fireVer, response_t.FireVer)
		//fqdn = fmt.Sprintf("smartfw/reqfire?deviceId=%d", Agent_t.deviceId)
		fqdn := fmt.Sprintf("smartfw/reqfire?uuid=%s", Agent_t.uuId)
		resp, err := cls.HttpSend(cls.TCP_SPHERE, "GET", fqdn, true)
		if err != nil {
			lprintf(1, "[ERROR] cls HttpSendRequest fail(%s) \n", err.Error())
		}

		if resp.StatusCode == 200 {
			_, Agent_t.fireVer = parseFireResponse(resp)
			lprintf(4, "[INFO] change agent firewall version (%d) \n", Agent_t.fireVer)
		}
	}

	/*
		FBlockTime -> SYN 플러드 발생 시 차단 시간(초), 현재 화면에 없음 0으로 사용
		FloodCnt   -> SYN 플러드 최대 횟수
		FloodTime -> SYN 플러드 최대 횟수 허용 시간(초)
		RBlockTime -> Slow Read 발생 시 차단 시간(초), 현재 화면에 없음 0으로 사용
		ReadMinSize -> 최소 트래픽
		ReadTime -> 최소 트래픽 허용 시간(초)

		2020.12.15 현재 화면에서 BlockTime이 없음
		0으로 내릴 시 무한정 Block 설정

		idle, fw에서 slow read, flooding에 해당하는 악성 ip block을 요청해도
		agent의 def use 값에 따라 region으로 보고만 하고 edge에는 block list rull을 추가 안함
		region에서 rull을 내리는 부분만 적용 됨
	*/

	// defence rule update(flood)
	if Agent_t.defVer != response_t.DefVer {
		lprintf(4, "[INFO] agent defence rule version (%d), response defence rule version (%d) different in op\n", Agent_t.defVer, response_t.DefVer)

		lprintf(4, "[INFO] FBlockTime(%d) \n", response_t.DefRule.FBlockTime)
		lprintf(4, "[INFO] FloodCnt(%d) \n", response_t.DefRule.FloodCnt)
		lprintf(4, "[INFO] FloodTime(%d) \n", response_t.DefRule.FloodTime)
		lprintf(4, "[INFO] RBlockTime(%d) \n", response_t.DefRule.RBlockTime)
		lprintf(4, "[INFO] ReadMinSize(%d) \n", response_t.DefRule.ReadMinSize)
		lprintf(4, "[INFO] ReadTime(%d) \n", response_t.DefRule.ReadTime)

		if insertDefence(response_t.DefVer, response_t.DefRule.FBlockTime, response_t.DefRule.FloodCnt, response_t.DefRule.FloodTime, response_t.DefRule.RBlockTime, response_t.DefRule.ReadMinSize, response_t.DefRule.ReadTime) != FAIL {
			_, Agent_t.defVer = floodToDevice()
			lprintf(4, "[INFO] change agent defence rule version (%d) \n", Agent_t.defVer)
		}
	}

	/*
		방화벽 커널을 사용 할때 sphere, station ip를 accept rull을 만들어서 module에 적용
		if fwUpdate > 0 {
			plgToWhite(Agent_t.rsphere, Agent_t.rstation)
		}
	*/

	// operation sort
	var tmpOps []Operation_s
	var tmpOp Operation_s
	opLen := len(response_t.Operation_t)

	for i := 0; i < opLen; i++ {
		if response_t.Operation_t[i].PlgName != "smartagent" {
			tmpOp = response_t.Operation_t[i]
			tmpOps = append(tmpOps, tmpOp)
		}
	}

	for i := 0; i < opLen; i++ {
		if response_t.Operation_t[i].PlgName == "smartagent" {
			tmpOp = response_t.Operation_t[i]
			tmpOps = append(tmpOps, tmpOp)
		}
	}

	for i := 0; i < len(tmpOps); i++ {
		response_t.Operation_t[i] = tmpOps[i]
	}

	// operation go
	for _, val := range response_t.Operation_t {

		lprintf(4, "========== Operation info ==========\n")

		/*
			OP_PLGINSTALL (plugin install 신규)
			OP_PLGUPDATE (plugin, profile update)
			OP_PLGDELETE (plugin delete)
			OP_PROUPDATE (profile update)
		*/

		lprintf(4, "[INFO] action(%d) \n", val.Action)
		lprintf(4, "[INFO] nicName = (%s)\n", val.NicName)
		lprintf(4, "[INFO] PlgName = (%s)\n", val.PlgName)
		lprintf(4, "[INFO] plgId = (%s)\n", val.PlgId)
		lprintf(4, "[INFO] plgVer = (%d)\n", val.PlgVer)
		lprintf(4, "[INFO] proId = (%s)\n", val.ProID)
		lprintf(4, "[INFO] proVer = (%d)\n", val.ProVer)

		var fileName, confName string // tar file name, conf name
		var plugin_t plugin_s         // install plugin struct

		if val.Action == OP_RESTART {
			lprintf(4, "[INFO] smartagent restart \n")
			os.Exit(0)
		}

		rst, plugin_f = FindPlg(val.PlgId)
		if rst < 0 {
			lprintf(4, "[INFO] PlgId(%s) not found in plugin list \n", val.PlgId)
		}

		if val.Action == OP_PLGDELETE {

			if len(val.PlgId) < 10 && plugin_f.pId > 0 {
				server_f.nicName = plugin_f.nicName
				server_f.pId = plugin_f.pId
				server_f.plgName = plugin_f.plgName
			} else {
				PlgStop(plugin_f)
			}

			PlgDelete(plugin_f)

			continue
		}

		if val.Action != OP_PROUPDATE {

			if val.PlgName == "smartstation" {
				setLogCollector()
			} else if val.PlgName == "db" {
				SqlOperation(INSERT, val)
				continue
			}

			lprintf(4, "[INFO] plugin download start \n")
			rst, fileName = DownFile(val.PlgId, val.PlgVer, ST_PLUGIN)
			if rst < 0 {
				lprintf(4, "[INFO] plugin download retry \n")
				rst, fileName = DownFile(val.PlgId, val.PlgVer, ST_PLUGIN)
				if rst < 0 {
					lprintf(1, "[ERROR] plugin download fail \n")
					continue
				}
			}

			if strings.Contains(fileName, ".gz") {
				//gzip decompress
				rst, fileName = GzipDecompress(fileName)
				if rst < 0 {
					lprintf(1, "[FAIL] gzip decompress fail \n")
					continue
				}
			}
		}

		lprintf(4, "[INFO] profile download start \n")
		rst, confName = DownFile(val.ProID, val.ProVer, ST_PROFILE)
		if rst < 0 {
			lprintf(4, "[INFO] profile download retry \n")
			rst, confName = DownFile(val.ProID, val.ProVer, ST_PROFILE)
			if rst < 0 {
				lprintf(1, "[ERROR] profile download fail \n")
				continue
			}
		}

		if val.PlgName == "smartagent" {
			lprintf(4, "[INFO] agent sel update start")
			SqlStatementEdge(UPDATE)
			SqlOperation(UPDATE, val)

			cmd = "> /etc/crontab"
			lprintf(4, "[INFO] run cmd(%s) start \n", cmd)
			RunCmd_N(cmd)

			if val.Action == OP_PROUPDATE {
				cmd = SMARTAGENT_PATH + "/cfg_update.sh"
			} else {
				cmd = SMARTAGENT_PATH + "/tar_update.sh " + fileName
			}

			lprintf(4, "[INFO] run cmd(%s) start \n", cmd)
			RunCmd_N(cmd)
			os.Exit(0)
		}

		if plugin_f.pId > 0 {
			PlgStop(plugin_f)
		}

		if val.Action != OP_PROUPDATE {

			if server_f.pId > 0 {
				PlgStop(server_f)
				server_f.pId = 0
			}

			lprintf(4, "[INFO] %s decompress start \n", fileName)
			if TarDeCompress(val.NicName, fileName) < 0 {

				backFile := val.PlgName + ".tar"
				BakToTmp(val.NicName, backFile)              // tar back file -> tmp
				TarDeCompress(val.NicName, backFile)         // file decompress
				ConfBack(val.PlgName, val.NicName, confName) // conf back file rollback
				PlgStart(plugin_f)                           // plg start

				continue
			}

			// plugin tmp to bak -> util
			lprintf(4, "[INFO] %s move tmp to bak start \n", fileName)
			TmpToBak(val.NicName, fileName, ST_PLUGIN)

		}

		lprintf(4, "[INFO] %s move tmp to right dir \n", confName)
		if ConfCopy(val.NicName, val.PlgName, confName) < 0 {
			lprintf(1, "[ERROR] %s move fail \n", confName)
		}

		// conf tmp to bak
		lprintf(4, "[INFO] %s move tmp to bak start \n", confName)
		TmpToBak(val.NicName, confName, ST_PROFILE)

		plugin_t.nicName = val.NicName
		plugin_t.plgId = val.PlgId
		plugin_t.plgVer = val.PlgVer
		plugin_t.proId = val.ProID
		plugin_t.proVer = val.ProVer
		plugin_t.plgState = YES
		plugin_t.plgNowState = YES
		plugin_t.plgName = val.PlgName

		// plugin install or update
		for i := 0; i < len(Agent_t.nic_t); i++ {
			if Agent_t.nic_t[i].nicName == val.NicName {

				if val.Action == OP_PLGINSTALL { // install
					Agent_t.nic_t[i].plugin_t = append(Agent_t.nic_t[i].plugin_t, plugin_t)
					SqlOperation(INSERT, val)
				} else { // update

					for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
						if Agent_t.nic_t[i].plugin_t[j].plgId == val.PlgId {
							Agent_t.nic_t[i].plugin_t[j] = plugin_t
							SqlOperation(UPDATE, val)
							break
						}
					}
				}
				break
			}
		}

		PlgStart(plugin_t)
	}

	// download cert
	for _, val := range response_t.Download_t {
		lprintf(4, "========== Cert info ==========\n")
		lprintf(4, "[INFO] action = (%d) \n", val.Action)
		lprintf(4, "[INFO] download certId = (%s) \n", val.CertId)
		//lprintf(4, "[INFO] download certVer = (%d) \n", val.CertVer)

		if val.Action == OP_PLGDELETE {
			if certDelete(val.CertId) < 0 {
				lprintf(1, "[FAIL] delete cert id(%s) fail \n", val.CertId)
			}
			continue
		}

		// download -> util
		rst, _ = DownFile(val.CertId, 0, ST_CERT)
		if rst < 0 {
			lprintf(1, "[ERROR] cert download fail \n")
			continue
		}

		rst, _ = DownFile(val.CertId, 0, ST_KEY)
		if rst < 0 {
			lprintf(1, "[ERROR] key download fail \n")
			continue
		}

		if SqlStatementCert(val.Action, 0, val.CertId) < 0 {
			lprintf(1, "[ERROR] sql statement fail, cert(%s) \n", val.CertId)
			continue
		}

		if val.Action == OP_PLGINSTALL {

			var ct cert_s
			ct.certId = val.CertId
			//ct.certVer = val.CertVer

			Agent_t.cert_t = append(Agent_t.cert_t, ct)

		} else if val.Action == OP_PLGUPDATE {

			for i := 0; i < len(Agent_t.cert_t); i++ {
				ac := Agent_t.cert_t[i]

				if ac.certId == val.CertId {
					ac.certId = val.CertId
					//ac.certVer = val.CertVer
					break
				}
			}

		}
	}

	/*
		if len(response_t.IdleDomain) > 0 {
			lprintf(4, "[INFO] idle domain is (%s) \n", response_t.IdleDomain)

			if Agent_t.siteId != 0 && Agent_t.manager == 0 {
				var notiData string
				for i := 0; i < len(response_t.IdleDomain); i++ {
					notiData += fmt.Sprintf("%s^", response_t.IdleDomain[i])
				}
				go notiMakeFile("DOMAIN", []byte(notiData))
			}
		}

		if len(response_t.DelBlack) > 0 {
			lprintf(4, "[INFO] del black is (%s) \n", response_t.DelBlack)

			delIp, resp := delBlack("")
			if resp < 0 {
				lprintf(1, "[FAIL] del black select fail \n")
				for i := 0; i < len(response_t.DelBlack); i++ {
					delBlack(response_t.DelBlack[i])
				}
			} else {
				for i := 0; i < len(response_t.DelBlack); i++ {
					for j := 0; j < len(delIp); j++ {
						if response_t.DelBlack[i] == delIp[j] {
							response_t.DelBlack[i] = "0"
						}
					}
				}

				for i := 0; i < len(response_t.DelBlack); i++ {
					if response_t.DelBlack[i] != "0" {
						delBlack(response_t.DelBlack[i])
					}
				}
			}

			if sqlToDevice() < 0 {
				lprintf(1, "[FAIL] sql to device fail \n")
				return FAIL
			}

		}
	*/

	return SUCCESS
}

/*
func doNotifire(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	//Wait.Wait()
	var bFlag, iFlag bool

	lprintf(4, "========== doNotifire info ==========\n")

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		lprintf(1, "[ERROR] requset body read fail(%s)\n", err.Error())
		cls.Renderer.Text(w, http.StatusOK, NT_BADREQ)
		return
	}

	lprintf(4, "[INFO] notifire parsing start(%s) \n", string(data))
	resp, notifire_t := parseNotifire(data)
	if resp < 0 {
		lprintf(1, "[FAIL] notifire parsing fail \n")
		cls.Renderer.Text(w, http.StatusOK, NT_BADREQ)
		return
	}

	lprintf(4, "[INFO] notifire list is (%d) - (0:white list, 1:black list) \n", notifire_t.List)
	lprintf(4, "[INFO] notifire command is (%d) - (0:insert, 1:delete) \n", notifire_t.Command)
	lprintf(4, "[INFO] notifire Source (%s)\n", notifire_t.Source)

	var rst int
	// set table name
	if notifire_t.List == 0 { // white list
		rst = insertRull(notifire_t)
	} else { // black list
		bFlag = true
		if Agent_t.defUse == YES { // deteck use
			rst = insertRull(notifire_t)
		}
	}

	if rst < 0 {
		cls.Renderer.Text(w, http.StatusOK, NT_FAIL)
		return
	}

	if notifire_t.Command == 0 {
		iFlag = true
	}

	//when black list insert, to sphere message
	if bFlag && iFlag {

		lprintf(4, "[INFO] black list insert, to sphere message \n")
		sendSphereFirewall(notifire_t)

	}

	lprintf(4, "========== doNotifire end ==========\n")

	cls.Renderer.Text(w, http.StatusOK, NT_SUCCESS)

}
*/

func doNotifire(data []byte) {

	//Wait.Wait()
	var bFlag, iFlag bool

	lprintf(4, "========== doNotifire info ==========\n")

	lprintf(4, "[INFO] notifire parsing start(%s) \n", string(data))
	resp, notifire_t := parseNotifire(data)
	if resp < 0 {
		lprintf(1, "[FAIL] notifire parsing fail \n")
		return
	}

	lprintf(4, "[INFO] notifire list is (%d) - (0:white list, 1:black list) \n", notifire_t.List)
	lprintf(4, "[INFO] notifire command is (%d) - (0:insert, 1:delete) \n", notifire_t.Command)
	lprintf(4, "[INFO] notifire Source (%s)\n", notifire_t.Source)

	var rst int
	// set table name
	if notifire_t.List == 0 { // white list
		rst = insertRull(notifire_t)
	} else { // black list
		bFlag = true
		if Agent_t.defUse == YES { // deteck use
			rst = insertRull(notifire_t)
		}
	}

	if rst < 0 {
		return
	}

	if notifire_t.Command == 0 {
		iFlag = true
	}

	//when black list insert, to sphere message
	if bFlag && iFlag {

		lprintf(4, "[INFO] black list insert, to sphere message \n")
		sendSphereFirewall(notifire_t)

	}

	lprintf(4, "========== doNotifire end ==========\n")

	return

}

/*
func sendSphereFirewall(notifire_t notiFirewall) {

	var reportJson reportfirewall
	reportJson.UuID = Agent_t.uuId
	reportJson.List = 1
	reportJson.Command = 0
	reportJson.Source = notifire_t.Source
	reportJson.Time = uint32(time.Now().Unix())
	//reportJson.Reason = "Slow Read"
	reportJson.Reason = notifire_t.Reason
	reportJson.Buff = notifire_t.Buff

	var clientIp string

	for i := 0; i < len(notifire_t.KeyList); i++ {

		clientIp = notifire_t.KeyList[i].Ip
		nowTime := int(time.Now().Unix())

		ClientInfo.Lock()
		inTime, exist := ClientInfo.m[clientIp]
		if exist && (nowTime-inTime < 10) { // 디텍트 보고 시 10초동안 동일한 client 정보는 1건만 보고
			continue
		}
		ClientInfo.m[clientIp] = nowTime
		ClientInfo.Unlock()

		reportJson.Port = notifire_t.KeyList[i].Port
		reportJson.Ip = notifire_t.KeyList[i].Ip
		reportJson.Period = uint32(notifire_t.KeyList[i].Period)
		reportJson.Service = getIdleCinfo(reportJson.Ip, "18900")

		// send Sphere to report
		reportByte, err := json.Marshal(reportJson)
		if err != nil {
			lprintf(1, "[FAIL] json marshal error  (%s)", err)
			continue
		}

		lprintf(4, "[INFO] report firewall json(%v) \n", reportJson)

		httpResp, err := cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
		if err != nil {
			lprintf(1, "[ERROR] cls HttpSendRequest fail, error(%s) retry \n", err.Error())
			httpResp, _ = cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
			continue
		}

		httpResp.Body.Close()
	}
}
*/

func sendSphereFirewall(notifire_t notiFirewall) {

	var reportJson SetPlusAttackReportOneParam

	reportJson.Uuid = Agent_t.uuId
	reportJson.ReportReason = notifire_t.Reason

	var clientIp string

	for i := 0; i < len(notifire_t.KeyList); i++ {

		clientIp = notifire_t.KeyList[i].Ip
		nowTime := int(time.Now().Unix())

		ClientInfo.Lock()
		inTime, exist := ClientInfo.m[clientIp]
		if exist && (nowTime-inTime < 10) { // 디텍트 보고 시 10초동안 동일한 client 정보는 1건만 보고
			ClientInfo.Unlock()
			continue
		}
		ClientInfo.m[clientIp] = nowTime
		ClientInfo.Unlock()

		reportJson.ClientIp = clientIp
		reportJson.Fqdn = getIdleCinfo(clientIp, "18900")

		// send Sphere to report
		reportByte, err := json.Marshal(reportJson)
		if err != nil {
			lprintf(1, "[FAIL] json marshal error  (%s)", err)
			continue
		}

		lprintf(1, "[INFO] report firewall json(%v) \n", reportJson)

		httpResp, err := cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
		if err != nil {
			lprintf(1, "[ERROR] cls HttpSendRequest fail, error(%s) retry \n", err.Error())
			httpResp, _ = cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
			continue
		}

		httpResp.Body.Close()
	}
}

func insertRull(notifire_t notiFirewall) int {

	var tblName, reason string

	// set table name
	if notifire_t.List == 0 {
		tblName = "WHITE_FW_TAB"
		reason = "Port Open"
	} else {
		tblName = "BLACK_FW_TAB"
		reason = "SLOWREAD"
	}

	for i := 0; i < len(notifire_t.KeyList); i++ {

		var stime, etime uint32

		// time set
		if notifire_t.KeyList[i].Period > 0 {
			stime = uint32(time.Now().Unix())
			etime = stime + uint32(notifire_t.KeyList[i].Period)
		}

		//insert
		if notifire_t.Command == 0 {
			//insertFW("BLACK_FW_TAB", "F", "I", reportJson.Ip, "0", reportJson.Time, reportJson.Time+FloodBlockTime, "0", "0", reportJson.Reason)
			//insertFW(tblName, div, dir, sip, dip string, stime, etime uint32, protocol, port, reason string) int {
			lprintf(4, "[INFO] insertFW tblName(%s) \n", tblName)
			insertReplaceFW(tblName, notifire_t.Source, "I", notifire_t.KeyList[i].Ip, "0", stime, etime, "TCP", strconv.Itoa(notifire_t.KeyList[i].Port), reason)
			//iFlag = true
			// delete
		} else if notifire_t.Command == 1 {
			//func deleteFW(tblName, dir, sip, port string, stime, etime uint32) int {
			lprintf(4, "[INFO] deleteFW tblName(%s) \n", tblName)
			deleteFW(tblName, "I", notifire_t.KeyList[i].Ip, strconv.Itoa(notifire_t.KeyList[i].Port), stime, etime)
		}

	}

	if sqlToDevice() == FAIL {
		//lprintf(1, "[FAIL] sql to device error \n")
		//cls.Renderer.Text(w, http.StatusOK, NT_FAIL)
		return FAIL
	}

	return SUCCESS

}

func doUuid(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	lprintf(4, "========== doUuid info ==========\n")

	cls.Renderer.Text(w, http.StatusOK, Agent_t.uuId)

}

func doPublic(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	lprintf(4, "========== doPublic info ==========\n")

	cls.Renderer.Text(w, http.StatusOK, Agent_t.nic_t[1].nicPubIp)

}

func doStat(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	//lprintf(4, "========== doStat info ==========\n")

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		lprintf(1, "[ERROR] requset body read fail(%s)\n", err.Error())
		cls.Renderer.Text(w, http.StatusOK, NT_BADREQ) // 통계 데이터 재전송 요망
		return
	}

	go writeStat(string(data))

	//dumData := string(data)

	//"<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<fqdn>[^,]*),(?<domain>[^,]*),(?<smartQuery>[^,]*),(?<cacheUse>[^,]*),(?<executionTime>[^,]*),(?<queryType>[^,]*),(?<respType>[^,]*),(?<respData>[^,]*),(?<utc>[^,]*),(?<kst>[^*]*)/\n</pattern>\n" // 10 dns

	//statData := fmt.Sprintf("%s", strings.TrimSpace(dumData))
	//cls.Lprints(1, statData)

	//lprintf(4, "[INFO] stat log write(%s) \n", statData)

	cls.Renderer.Text(w, http.StatusOK, NT_SUCCESS) // 통계 데이터 성공
}

func doNotifyTcp(port string) {

	rst, nic := setNetworkInfo()
	if rst < 0 {
		lprintf(1, "[ERROR] stat listen ip get fail(%s) \n")
		return
	}

	listen := fmt.Sprintf("%s:%s", nic[1].nicIp, port)

	lprintf(4, "[INFO] agent notify listen ip(%s) \n", listen)

	tcpAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		lprintf(1, "[ERROR] ResolveTCPAddr(%s), error(%s) \n", listen, err.Error())
		return
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		lprintf(1, "[ERROR] ListenTCP(%), error(%s) \n", listen, err.Error())
		return
	}
	defer listener.Close()

	//lprintf(4, "[INFO] listen info(%s)", listen)

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			lprintf(1, "[ERROR] listener accept error(%s) \n", err.Error())
			continue
		}

		go statHandler(conn)
	}
}

func statHandler(lcon *net.TCPConn) {

	/*
		socket close 0으로 설정 시
		해당 socket close 시 상대방에게 RST 패킷을 전송하고, 자신의 소캣은 CLOSED 상태가 된다.
		커널의 송수신 버퍼에 보관 중인 내용은 즉시 모두 폐기된다.
	*/

	//lcon.SetLinger(0) // close -> RST packet (socket linger option)
	defer lcon.Close()

	for {

		buf, rst, sIndex, eIndex, url := readHttp(lcon)
		if rst < 0 {
			lcon.SetLinger(0)
			return
		}

		lprintf(4, "[INFO] url(%s) \n", url)
		/*
			{cls.GET, "/smartagent/notify", doNotify, nil},     // 종합
			{cls.GET, "/smartagent/notifire", doNotifire, nil}, // 시스템 방화벽 룰
			{cls.GET, "/smartagent/stat", doStat, nil},
			{cls.GET, "/smartagent/uuid", doUuid, nil},
			{cls.GET, "/smartagent/getPublic", doPublic, nil},
		*/

		body := buf[sIndex:eIndex]

		respData := NT_SUCCESS

		if strings.Contains(url, "/smartagent/notify") {
			go doNotify(body)
		} else if strings.Contains(url, "/smartagent/notifire") {
			go doNotifire(body)
		} else if strings.Contains(url, "/smartagent/stat") {
			go writeStat(string(body))
		} else if strings.Contains(url, "/smartagent/uuid") {
			respData = Agent_t.uuId
		} else if strings.Contains(url, "/smartagent/getPublic") {
			respData = Agent_t.nic_t[1].nicPubIp
		} else {
			continue
		}

		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: agent\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(respData), respData)

		lprintf(4, "[INFO] resp ok(%s) \n", resp)

		lcon.Write([]byte(resp))
	}

}

func readHttp(lcon *net.TCPConn) ([]byte, int, int, int, string) {
	bufsize := 1024
	rbuf := make([]byte, bufsize)

	var readLen, idx int

	for {
		if readLen >= bufsize {
			bufsize = bufsize + 1024
			newbuf := make([]byte, 1024)
			rbuf = append(rbuf, newbuf...)
		}

		rlen, err := lcon.Read(rbuf[readLen:])
		if err != nil {
			if err != io.EOF {
				lprintf(1, "[ERROR] http body read error(%s) \n", err.Error())
			}
			return rbuf, FAIL, FAIL, FAIL, ""
		}

		readLen = readLen + rlen

		//lprintf(4, "[INFO] header get(%s), readlen(%d), rlen(%d) \n", string(rbuf[:readLen]), readLen, rlen)

		if idx = bytes.Index(rbuf[:readLen], []byte("\r\n\r\n")); idx > 0 { // read header all
			break
		}
	}

	var url string
	var s int

	for i := 0; i < readLen; i++ {
		if rbuf[i] == ' ' {
			if s == 0 {
				s = i + 1
			} else {
				url = string(rbuf[s:i])
			}
			continue
		}

		if rbuf[i] == '\r' {
			break
		}
	}

	//lprintf(4, "[INFO] idx(%d) \n", idx)
	//lprintf(4, "[INFO] rbuf(%x) \n", rbuf)
	//lprintf(4, "[INFO] rbuf[idx+4:readLen](%x) \n", rbuf[idx+4:readLen])

	//return rbuf[idx+4 : readLen], SUCCESS
	return rbuf, SUCCESS, idx + 4, readLen, url
}

func writeStat(stat string) {

	/*
		<router>
		smartrouter,read/write, fqdn, 접속경로, domain, len, 장비간 속도 체크, src ip

		<idle>
		smartidle,read/write, fqdn, len, domain, src ip

		<dns>
		smartdns,domain, fqdn
	*/

	var statData string
	datas := strings.Split(stat, ",")

	if len(datas) < 2 {
		lprintf(1, "[FAIL] stat data(%s) \n", datas)
		return
	}

	// utc, kst 데이터 판단 여부
	if strings.Contains(datas[len(datas)-1], ":") {
		statData = fmt.Sprintf("%s", strings.TrimSpace(stat))
	} else {
		nowTime := time.Now()
		utc := nowTime.UTC().Format("2006-01-02 15:04:05")
		loc, err := time.LoadLocation("Asia/Seoul")
		if err != nil {
			lprintf(1, "[ERROR] LoadLocation err(%s) \n", err.Error())
			return
		}

		kst := nowTime.In(loc).Format("2006-01-02 15:04:05")

		statData = fmt.Sprintf("%s,%s,%s", strings.TrimSpace(stat), utc, kst)
	}

	nowTime := int(time.Now().Unix())

	FqdnMap.Lock()
	p, exists := FqdnMap.m[datas[2]] // fqdn
	defer FqdnMap.Unlock()

	if exists && nowTime-p.InTime < Agent_t.reportInterval {
		statData = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", statData, p.ProviderIndex, p.ProviderName, p.UserIndex, p.CacheYN, p.ClientYN, p.DomainYN)
		p.InTime = nowTime
		FqdnMap.m[datas[2]] = p
		cls.Lprints(1, statData)
		return
	}

	/*
		if !exists {
			p = make(map[string]Provider)
		}
	*/

	var req fqdnProvider
	req.Fqdn = datas[2]
	reqJson, err := json.Marshal(req)
	if err != nil {
		lprintf(1, "[ERROR] json make err(%s) \n", err.Error())
		statData = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", statData, "", "", "", "", "", "")
		cls.Lprints(1, statData)
		return
	}

	httpResp, err := cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/fqdnProvider", reqJson, true)
	if err != nil {
		lprintf(1, "[ERROR] sphere get provider err(%s) \n", err.Error())
		statData = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", statData, "", "", "", "", "", "")
		cls.Lprints(1, statData)
		return
	}
	//defer httpResp.Body.Close()

	respdata, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		lprintf(1, "[ERROR] response body read err(%s) \n", err.Error())
		statData = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", statData, "", "", "", "", "", "")
		cls.Lprints(1, statData)
		httpResp.Body.Close()
		return
	}
	httpResp.Body.Close()

	rst, pInfo := parseProvider(respdata)
	if rst < 0 {
		lprintf(1, "[ERROR] parse provider err \n")
		statData = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", statData, "", "", "", "", "", "")
		cls.Lprints(1, statData)
		return
	}

	p.Domain = pInfo.Domain
	p.Host = pInfo.Host
	p.InTime = nowTime
	p.ProviderIndex = pInfo.ProviderIndex
	p.ProviderName = pInfo.ProviderName

	p.UserIndex = pInfo.UserIndex
	p.CacheYN = pInfo.CacheYN
	p.ClientYN = pInfo.ClientYN
	p.DomainYN = pInfo.DomainYN

	FqdnMap.m[datas[2]] = p

	statData = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", statData, pInfo.ProviderIndex, pInfo.ProviderName, pInfo.UserIndex, pInfo.CacheYN, p.ClientYN, p.DomainYN)

	lprintf(4, "[INFO] stat data(%s) \n", statData)

	cls.Lprints(1, statData)
	return

}

/*
func doNotify(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	lprintf(4, "========== doNotify info ==========\n")

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		lprintf(1, "[ERROR] requset body read fail(%s)\n", err.Error())
		cls.Renderer.Text(w, http.StatusOK, NT_BADREQ)
		return
	}

	resp, notify_t := parseNoti(data)
	if resp < 0 {
		lprintf(4, "[INFO] nofity parsing fail \n")
		cls.Renderer.Text(w, http.StatusOK, NT_BADREQ)
		return
	}

	lprintf(4, "[INFO] noti(%d) cache domain(%s), host(%s) crawling fqdn(%s) port(%s) ip(%s) protocol(%s) \n", notify_t.Notify, notify_t.CachePath.Domain, notify_t.CachePath.Host, notify_t.Crawling.Fqdn, notify_t.Crawling.Port, notify_t.Crawling.TargetIp, notify_t.Crawling.Protocol)

	var notiData string
	if notify_t.Notify == NT_FIREWALL { // get firewall user rull and send report message

		lprintf(4, "[INFO] notify firewall now ver(%d) \n", Agent_t.fireVer)

		fqdn := fmt.Sprintf("smartfw/reqfire?uuid=%s", Agent_t.uuId)
		resp, err := cls.HttpSend(cls.TCP_SPHERE, "GET", fqdn, true)
		if err != nil {
			lprintf(1, "[ERROR] cls HttpSendRequest fail(%s) \n", err.Error())
			cls.Renderer.Text(w, http.StatusOK, NT_FAIL)
			return
		}

		if resp.StatusCode != 200 {
			lprintf(1, "[ERROR] cls HttpSendRequest resp statusCode not 200 (%d) \n", resp.StatusCode)
			cls.Renderer.Text(w, http.StatusOK, NT_FAIL)
			return
		}

		_, fv := parseFireResponse(resp)
		Mu.Lock()
		Agent_t.fireVer = fv
		Mu.Unlock()

		lprintf(4, "[INFO] change agent firewall version (%d) \n", fv)

	} else if notify_t.Notify == NT_IDLE { // domain noti send to idle

		// plus on 설정 된 fqdn이 내려옴 **
		lprintf(4, "[INFO] notify idle domain(%s) \n", notify_t.Domain)

		//if Agent_t.siteId != 0 && Agent_t.manager == 0 {
		notiData = fmt.Sprintf("%s", notify_t.Domain)
		go notiMakeFile("DOMAIN", "smartidle", notiData)

		cls.Renderer.Text(w, http.StatusOK, NT_SUCCESS)
		return
		//}

	} else if notify_t.Notify == NT_CACHE {

		for j := 0; j < len(Agent_t.nic_t); j++ {
			rst, _ := FindPlgNic(Agent_t.nic_t[j].nicName, "smartidle")
			if rst > 0 {
				notiData := fmt.Sprintf("/%s/%s/%s", Agent_t.nic_t[j].nicName, notify_t.CachePath.Domain, notify_t.CachePath.Host)
				go notiMakeFile("DELCACHE", "smartidle", notiData)

			}
		}

		cls.Renderer.Text(w, http.StatusOK, NT_SUCCESS)
		return

	} else if notify_t.Notify == NT_DEFVER { // def ver change 0 and send report message

		lprintf(4, "[INFO] notify def rull \n")

		Mu.Lock()
		Agent_t.defVer = 0
		Mu.Unlock()

	} else if notify_t.Notify == NT_SETCRAWLING { // crwaling fqdn 단위 시작
		lprintf(4, "[INFO] crawling start fqdn(%s) \n", notify_t.Crawling.Fqdn)
		data := fmt.Sprintf("%s/%s/%s/%s", notify_t.Crawling.Fqdn, notify_t.Crawling.Port, notify_t.Crawling.TargetIp, notify_t.Crawling.Protocol)
		go notiMakeFile("STARTCRAWLING", "smartcrawler", data)

	} else if notify_t.Notify == NT_DELCRAWLING { // crwaling fqdn 단위 종료
		lprintf(4, "[INFO] crawling stop fqdn(%s) \n", notify_t.Crawling.Fqdn)
		data := fmt.Sprintf("%s/%s/%s/%s", notify_t.Crawling.Fqdn, notify_t.Crawling.Port, notify_t.Crawling.TargetIp, notify_t.Crawling.Protocol)
		go notiMakeFile("STOPCRAWLING", "smartcrawler", data)

	} else { // noti code fail
		lprintf(4, "[INFO] nofity code(%d) fail \n", notify_t.Notify)
		cls.Renderer.Text(w, http.StatusOK, NT_BADREQ)
		return
	}

	lprintf(4, "[INFO] smartagent report now send \n")

	nowTime := int(time.Now().Unix())
	LastTime = nowTime - Agent_t.reportInterval
	LastNetTime = nowTime - Agent_t.reportInterval - 10

	cls.Renderer.Text(w, http.StatusOK, NT_SUCCESS)

}
*/

func doNotify(data []byte) {

	lprintf(4, "========== doNotify info ==========\n")

	resp, notify_t := parseNoti(data)
	if resp < 0 {
		lprintf(4, "[INFO] nofity parsing fail \n")
		return
	}

	lprintf(4, "[INFO] noti(%d) cache domain(%s), host(%s) crawling fqdn(%s) port(%s) ip(%s) protocol(%s) \n", notify_t.Notify, notify_t.CachePath.Domain, notify_t.CachePath.Host, notify_t.Crawling.Fqdn, notify_t.Crawling.Port, notify_t.Crawling.TargetIp, notify_t.Crawling.Protocol)

	var notiData string
	if notify_t.Notify == NT_FIREWALL { // get firewall user rull and send report message

		lprintf(4, "[INFO] notify firewall now ver(%d) \n", Agent_t.fireVer)

		fqdn := fmt.Sprintf("smartfw/reqfire?uuid=%s", Agent_t.uuId)
		resp, err := cls.HttpSend(cls.TCP_SPHERE, "GET", fqdn, true)
		if err != nil {
			lprintf(1, "[ERROR] cls HttpSendRequest fail(%s) \n", err.Error())
			return
		}

		_, fv := parseFireResponse(resp)
		resp.Body.Close()

		Mu.Lock()
		Agent_t.fireVer = fv
		Mu.Unlock()

		lprintf(4, "[INFO] change agent firewall version (%d) \n", fv)

	} else if notify_t.Notify == NT_IDLE { // domain noti send to idle

		// plus on 설정 된 fqdn이 내려옴 **
		lprintf(4, "[INFO] notify idle domain(%s) \n", notify_t.Domain)

		//if Agent_t.siteId != 0 && Agent_t.manager == 0 {
		notiData = fmt.Sprintf("%s", notify_t.Domain)
		go notiMakeFile("DOMAIN", "smartidle", notiData)

		return
		//}

	} else if notify_t.Notify == NT_CACHE {

		for j := 0; j < len(Agent_t.nic_t); j++ {
			rst, _ := FindPlgNic(Agent_t.nic_t[j].nicName, "smartidle")
			if rst > 0 {
				/*
					for i := 0; i < len(notify_t.CachePath); i++ {
						notiData += fmt.Sprintf("/%s/%s/%s^", Agent_t.nic_t[j].nicName, notify_t.CachePath[i].Domain, notify_t.CachePath[i].Host)
					}
				*/

				notiData := fmt.Sprintf("/%s/%s/%s", Agent_t.nic_t[j].nicName, notify_t.CachePath.Domain, notify_t.CachePath.Host)
				go notiMakeFile("DELCACHE", "smartidle", notiData)

			}
		}

		return

	} else if notify_t.Notify == NT_DEFVER { // def ver change 0 and send report message

		lprintf(4, "[INFO] notify def rull \n")

		Mu.Lock()
		Agent_t.defVer = 0
		Mu.Unlock()

	} else if notify_t.Notify == NT_SETCRAWLING { // crwaling fqdn 단위 시작
		lprintf(4, "[INFO] crawling start fqdn(%s) \n", notify_t.Crawling.Fqdn)
		data := fmt.Sprintf("%s/%s/%s/%s", notify_t.Crawling.Fqdn, notify_t.Crawling.Port, notify_t.Crawling.TargetIp, notify_t.Crawling.Protocol)
		go notiMakeFile("STARTCRAWLING", "smartcrawler", data)

	} else if notify_t.Notify == NT_DELCRAWLING { // crwaling fqdn 단위 종료
		lprintf(4, "[INFO] crawling stop fqdn(%s) \n", notify_t.Crawling.Fqdn)
		data := fmt.Sprintf("%s/%s/%s/%s", notify_t.Crawling.Fqdn, notify_t.Crawling.Port, notify_t.Crawling.TargetIp, notify_t.Crawling.Protocol)
		go notiMakeFile("STOPCRAWLING", "smartcrawler", data)

	} else { // noti code fail
		lprintf(4, "[INFO] nofity code(%d) fail \n", notify_t.Notify)
		return
	}

	lprintf(4, "[INFO] smartagent report now send \n")

	nowTime := int(time.Now().Unix())
	LastTime = nowTime - Agent_t.reportInterval
	LastNetTime = nowTime - Agent_t.reportInterval - 10

	return

}

// read and write device and insert sqlite
func parseFireResponse(resp *http.Response) (int, int) {

	rData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lprintf(1, "[ERROR] response body read err(%s) \n", err.Error())
		return FAIL, 0
	}
	respData := string(rData[:])
	defer resp.Body.Close()

	lprintf(4, "[INFO] parseJson start respData(%s)\n", respData)

	ret, ver := xmlToDevice(respData)
	if ret == FAIL {
		lprintf(1, "[ERROR] xml parse and send device error \n")
		return FAIL, 0
	}

	if insertXML(respData) == FAIL {
		lprintf(1, "[ERROR] insert xml to sqlite error\n")
		return FAIL, 0
	}

	lprintf(4, "[INFO] parseFireResponse ver(%d)", ver)

	return SUCCESS, ver
}

// parsing response json data and operation
func parseResponse(resp *http.Response) int {

	//defer resp.Body.Close()

	if resp.StatusCode != 200 {
		lprintf(1, "[ERROR] cls HttpSendRequest fail, resp code(%d)\n", resp.StatusCode)
		return FAIL
	}

	respdata, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lprintf(1, "[ERROR] response body read err(%s) \n", err.Error())
		resp.Body.Close()
		return FAIL
	}
	resp.Body.Close()

	lprintf(4, "[INFO] parseJson start \n")

	respParse, response_t := parseJson(respdata)

	if respParse < 0 {
		lprintf(1, "[ERROR] parseJson error \n")
		return FAIL
	}

	printResponse(response_t)

	lprintf(4, "[INFO] do operation start \n")
	respOp := doOp(response_t)
	if respOp < 0 {
		lprintf(1, "[ERROR] response data op, commnad fail \n")
		return FAIL
	}

	if respOp > SUCCESS {
		lprintf(4, "[INFO] do operation SqlUpdateEdge start \n")
		if SqlStatementEdge(UPDATE) < 0 {
			lprintf(1, "[ERROR] edge table inseart error \n")
			return FAIL
		}
	}

	return SUCCESS
}

func printResponse(response_t response) {

	lprintf(4, "[INFO] -- response print start -- \n")

	lprintf(4, "[INFO] dev name = %s \n", response_t.DeviceName)

	lprintf(4, "[INFO] def ver = %d \n", response_t.DefVer)
	lprintf(4, "[INFO] fire ver = %d \n", response_t.FireVer)

	lprintf(4, "[INFO] FBlockTime = %d \n", response_t.DefRule.FBlockTime)
	lprintf(4, "[INFO] FloodCnt = %d \n", response_t.DefRule.FloodCnt)
	lprintf(4, "[INFO] FloodTime = %d \n", response_t.DefRule.FloodTime)
	lprintf(4, "[INFO] RBlockTime = %d \n", response_t.DefRule.RBlockTime)
	lprintf(4, "[INFO] ReadMinSize = %d \n", response_t.DefRule.ReadMinSize)
	lprintf(4, "[INFO] ReadTime = %d \n", response_t.DefRule.ReadTime)

	lprintf(4, "[INFO] sphere uuid = %s \n", response_t.UuID)
	lprintf(4, "[INFO] sphere ip = %s \n", response_t.RSphere)
	lprintf(4, "[INFO] station ip = %s \n", response_t.RStation)
	lprintf(4, "[INFO] db ip = %s \n", response_t.RDb)
	lprintf(4, "[INFO] crawler ip = %s \n", response_t.RCrawl)

	for i := 0; i < len(response_t.Operation_t); i++ {

		lprintf(4, "[INFO] Action = %d(0-plg install, 1-plg update, 2-plg delete, 3-pro update) \n", response_t.Operation_t[i].Action)
		lprintf(4, "[INFO] NicName = %s \n", response_t.Operation_t[i].NicName)
		lprintf(4, "[INFO] PlgName = %s \n", response_t.Operation_t[i].PlgName)
		lprintf(4, "[INFO] PlgId = %s \n", response_t.Operation_t[i].PlgId)
		lprintf(4, "[INFO] PlgVer = %d \n", response_t.Operation_t[i].PlgVer)
		lprintf(4, "[INFO] ProId = %s \n", response_t.Operation_t[i].ProID)
		lprintf(4, "[INFO] ProVer = %d \n", response_t.Operation_t[i].ProVer)
	}

	for j := 0; j < len(response_t.Download_t); j++ {
		lprintf(4, "[INFO] Action = %d(0-cert install, 1-cert update, 2-cert delete) \n", response_t.Download_t[j].Action)
		lprintf(4, "[INFO] CertId = %s \n", response_t.Download_t[j].CertId)
		//lprintf(4, "[INFO] CertVer = %d \n", response_t.Download_t[j].CertVer)
	}

	lprintf(4, "[INFO] -- response print finish -- \n")

}

// init install plugin
func initPlugin(id, proId, plgName string, ver, proVer int) int {

	var val Operation_s
	var plugin_t plugin_s

	//val.Action = OP_INSTALL
	val.NicName = DEFAULT_NIC
	val.PlgId = id
	val.PlgVer = ver
	val.ProID = proId
	val.ProVer = proVer
	val.PlgName = plgName

	if SqlOperation(INSERT, val) < 0 {
		lprintf(1, "[ERROR] sql smartagent insert fail \n")
		return FAIL
	}

	//setting agent struct
	plugin_t.plgName = plgName
	plugin_t.nicName = DEFAULT_NIC
	plugin_t.plgId = id
	plugin_t.plgVer = ver
	plugin_t.proId = proId
	plugin_t.proVer = proVer
	plugin_t.plgState = YES
	plugin_t.plgNowState = YES

	lprintf(4, "[INFO] init plugin plgId(%s), plgVer(%d), proId(%s), proVer(%d), plgName(%s) \n", plugin_t.plgId, plugin_t.plgVer, plugin_t.proId, plugin_t.proVer, plugin_t.plgName)

	Agent_t.nic_t[0].plugin_t = append(Agent_t.nic_t[0].plugin_t, plugin_t)

	return SUCCESS
}

func setLogCollector() int {

	var serverIp, serverConf, targetIp string
	var flag bool

	if FindPlgName("smartstation") {
		flag = true
		targetIp = Agent_t.mfluentd
	} else {
		flag = false
		targetIp = Agent_t.rstation
	}

	if len(targetIp) == 0 {
		return SUCCESS
	}

	ip := strings.Split(targetIp, "&")
	ipIndex := rand.Intn(len(ip)) // ipIndex = 0 ~ n
	serverIp = ip[ipIndex]

	lprintf(4, "[INFO] set log colleector ip(%s), flag(%v) \n", serverIp, flag)

	if flag {

		serverConf = "<source>\n@type forward\nport 24224\ntag mongodb\n</source>\n\n"

		serverConf += "<source>\n@type tail\npath /var/log/hydraplus.log\npos_file /tmp/hydraplus.pos\ntag mongodb\n"
		serverConf += "<parse>\n@type multi_format\n"
		serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<devName>[^,]*),(?<cpu>[^,]*),(?<mem>[^,]*),(?<swap>[^,]*),(?<disk>[^,]*),(?<net>[^,]*),(?<publicIp>[^,]*),(?<utc>[^,]*),(?<kst>[^*]*)/\n</pattern>\n" // 13 agent
		serverConf += "</parse>\n</source>\n\n"

		serverConf += "<match mongodb>\n@type forward\nflush_interval 5s\n<server>\n"
		//serverConf += "<match mongodb>\n@type forward\n<server>\n"
		serverConf += "host " + serverIp + "\n"
		serverConf += "port 24224\n</server>\n</match>"

		/*
			if Agent_t.mT == 1 {
				return SUCCESS
			}

			serverConf = "<source>\n@type forward\nport 24224\ntag data\n</source>\n\n"
			serverConf += "<match data>\n@type rewrite_tag_filter\n"
			serverConf += "<rule>\nkey name\npattern /smartrouter/\ntag smartrouter\n</rule>\n"
			serverConf += "<rule>\nkey name\npattern /smartidle/\ntag smartidle\n</rule>\n"
			serverConf += "<rule>\nkey name\npattern /smartdns/\ntag smartdns\n</rule>\n"
			serverConf += "</match>\n\n"

			serverConf += "<match smartidle>\n@type mongo\nhost " + Agent_t.mH + "\nport " + Agent_t.mP + "\ndatabase " + Agent_t.mD + "\ncollection "
			if len(Agent_t.mC) > 0 {
				serverConf += Agent_t.mC + "\nuser " + Agent_t.mU + "\npassword " + Agent_t.mPW + "\nflush_interval 5s\n</match>\n\n"
			} else {
				serverConf += "smartidle" + "\nuser " + Agent_t.mU + "\npassword " + Agent_t.mPW + "\nflush_interval 5s\n</match>\n\n"
			}

			serverConf += "<match smartdns>\n@type mongo\nhost " + Agent_t.mH + "\nport " + Agent_t.mP + "\ndatabase " + Agent_t.mD + "\ncollection "
			if len(Agent_t.mC) > 0 {
				serverConf += Agent_t.mC + "\nuser " + Agent_t.mU + "\npassword " + Agent_t.mPW + "\nflush_interval 5s\n</match>\n\n"
			} else {
				serverConf += "smartdns" + "\nuser " + Agent_t.mU + "\npassword " + Agent_t.mPW + "\nflush_interval 5s\n</match>\n\n"
			}

			serverConf += "<match smartrouter>\n@type mongo\nhost " + Agent_t.mH + "\nport " + Agent_t.mP + "\ndatabase " + Agent_t.mD + "\ncollection "
			if len(Agent_t.mC) > 0 {
				serverConf += Agent_t.mC + "\nuser " + Agent_t.mU + "\npassword " + Agent_t.mPW + "\nflush_interval 5s\n</match>"
			} else {
				serverConf += "smartrouter" + "\nuser " + Agent_t.mU + "\npassword " + Agent_t.mPW + "\nflush_interval 5s\n</match>"
			}
		*/

	} else {

		//lprintf(4, "[INFO] station all ip(%s) \n", Agent_t.rstation)

		serverConf = "<source>\n@type tail\npath /var/log/hydraplus.log\npos_file /tmp/hydraplus.pos\ntag mongodb\n"
		serverConf += "<parse>\n@type multi_format\n"

		/*
			if FindPlgName("smartdns") {
				serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<fqdn>[^,]*),(?<domain>[^,]*),(?<smartQuery>[^,]*),(?<cacheUse>[^,]*),(?<executionTime>[^,]*),(?<queryType>[^,]*),(?<respType>[^,]*),(?<respData>[^,]*),(?<utc>[^,]*),(?<kst>[^*]*)/\n</pattern>\n" // 10 dns
			}

			fluentd config record 갯수 순으로 작성해야 동작 함
		*/

		// pInfo.UserIndex, pInfo.CacheYN, p.ClientYN, p.DomainYN

		if FindPlgName("nginx") {
			serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<type>[^,]*),(?<fqdn>[^,]*),(?<x-proxyUser-Ip>[^,]*),(?<domain>[^,]*),(?<traffic>[^,]*),(?<x-proxyEdge-Time>[^,]*),(?<clientIp>[^,]*),(?<utc>[^,]*),(?<kst>[^,]*),(?<providerIndex>[^,]*),(?<providerName>[^,]*),(?<userIndex>[^,]*),(?<cacheYn>[^,]*),(?<clientYn>[^,]*),(?<domainYn>[^*]*)/\n</pattern>\n" // 19 router
			//serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<type>[^,]*),(?<fqdn>[^,]*),(?<traffic>[^,]*),(?<domain>[^,]*),(?<packet>[^,]*),(?<utc>[^,]*),(?<kst>[^*]*)/\n</pattern>\n"                                    // 7 idle
			serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<type>[^,]*),(?<fqdn>[^,]*),(?<traffic>[^,]*),(?<domain>[^,]*),(?<clientIp>[^,]*),(?<clientPort>[^,]*),(?<utc>[^,]*),(?<kst>[^,]*),(?<providerIndex>[^,]*),(?<providerName>[^,]*),(?<userIndex>[^,]*),(?<cacheYn>[^,]*),(?<clientYn>[^,]*),(?<domainYn>[^*]*)/\n</pattern>\n" // 18 idle
		}
		if FindPlgName("smartdns") {
			serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<domain>[^,]*),(?<fqdn>[^,]*),(?<utc>[^,]*),(?<kst>[^,]*),(?<providerIndex>[^,]*),(?<providerName>[^,]*),(?<userIndex>[^,]*),(?<cacheYn>[^,]*),(?<clientYn>[^,]*),(?<domainYn>[^*]*)/\n</pattern>\n" // 14 dns
		}
		serverConf += "<pattern>\nformat /^(?<day>[^ ]*) (?<serverTime>[^ ]*) (?<uuId>[^,]*),(?<name>[^,]*),(?<devName>[^,]*),(?<cpu>[^,]*),(?<mem>[^,]*),(?<swap>[^,]*),(?<disk>[^,]*),(?<net>[^,]*),(?<publicIp>[^,]*),(?<utc>[^,]*),(?<kst>[^*]*)/\n</pattern>\n" // 13 agent

		serverConf += "</parse>\n</source>\n"
		serverConf += "<match mongodb>\n@type forward\nflush_interval 5s\n<server>\nhost " + serverIp + "\nport 24224\n</server>\n</match>"
		//serverConf += "<match mongodb>\n@type forward\n<server>\nhost " + serverIp + "\nport 24224\n</server>\n</match>"

	}

	byteData := []byte(serverConf)

	err := ioutil.WriteFile("/etc/td-agent/td-agent.conf", byteData, 644)
	if err != nil {
		lprintf(1, "[ERROR] log collector conf set error(%s)\n", err.Error())
		return FAIL
	}

	RunCmd_N("/etc/init.d/td-agent restart")

	return SUCCESS

}

// after plugin update
func callBackUpdate(plg plugin_s) int {

	lprintf(4, "[INFO] after plugin(%s) update, call back fun \n", plg.plgName)

	switch plg.plgName {
	case "smartidle":
		Agent_t.defVer = 0   // slow read
		Agent_t.rsphere = "" // set sphere ip
	case "smartdns":
		Agent_t.rsphere = "" // set sphere ip
	case "smartrouter":
		Agent_t.rsphere = "" // set sphere ip
	case "smartfw":
		//notiMakeFile([]byte(Agent_t.rdomain)) // noti domain write
		sqlToDevice()       // white, black rull to device
		Agent_t.defVer = 0  // flood rull to device
		Agent_t.fireVer = 0 // user xml rull to device
	case "smartstation":
		Agent_t.rdb = "" // sphere, station db ip set
	case "nginx":
		resp, idle := FindPlgNic(plg.nicName, "smartidle")
		if resp > 0 {
			PlgStop(idle)
		}
	default:
		lprintf(4, "[INFO] do not callBack \n")
		return SUCCESS
	}

	// noti agent
	nowTime := int(time.Now().Unix())
	LastTime = nowTime - Agent_t.reportInterval
	LastNetTime = nowTime - Agent_t.reportInterval - 10

	return SUCCESS
}

func notiMakeFile(key, plgName, fileData string) int {

	if len(fileData) == 0 {
		return SUCCESS
	}

	if len(plgName) > 0 && !FindPlgName(plgName) {
		return SUCCESS
	}

	lprintf(4, "[INFO] notify data(%s) \n", fileData)

	if len(key) > 0 {
		fileData = key + "=" + fileData
		notiMakeData(plgName, fileData)
	} else {
		for i := 0; i < len(Agent_t.nic_t); i++ {
			for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
				if strings.Contains("smartagent smartfw smartsphere smartstation nginx db", Agent_t.nic_t[i].plugin_t[j].plgName) {
					continue
				}

				go notiMakeData(Agent_t.nic_t[i].plugin_t[j].plgName, fileData)

			}
		}
	}

	return SUCCESS
}

func notiMakeData(fileName, fileData string) {

	MakeDir(SMARTAGENT_TMP + "/" + fileName)

	var filePath string

	for i := 0; i < 2; i++ {

		if i == 0 {
			filePath = SMARTAGENT_TMP + "/" + fileName + "/scale.data"
		} else {
			filePath = SMARTAGENT_TMP + "/" + fileName + "/scale.ctl"
		}

		if FileExist(filePath) {
			lprintf(4, "[INFO] file(%s) exist \n", filePath)
			time.Sleep(2 * time.Second)
			if FileExist(filePath) {
				continue
			}
		}

		input, err := os.Create(filePath)
		if err != nil {
			lprintf(1, "[ERROR] file create fail(%s) \n", filePath)
			return
		}
		//defer

		writeData := cls.EEncode([]byte(fileData))

		_, err = input.Write([]byte(writeData))
		if err != nil {
			input.Close()
			lprintf(1, "[ERROR] file write fail(%s), data(%s) \n", filePath, fileData)
			return
		}
		input.Close()

	}

}
