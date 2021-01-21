/*
	smartagent utility
*/

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"charlie/i0.0.2/cls"
)

/*
func GetDISK() (free, total uint64) {
	fs := syscall.Statfs_t{}
	err := syscall.Statfs("/", &fs)
	if err != nil {
		lprintf(1, "[ERROR] disk check error(%s) \n", err.Error())
		return
	}
	total = fs.Blocks * uint64(fs.Bsize)
	free = fs.Bfree * uint64(fs.Bsize)

	return
}
*/

// mpstat | tail -1 | awk '{print 100-$11}'
// return cpu user usage, total usage
/*
func GetUserCPU() (user, total uint64) {
	contents, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		lprintf(1, "[ERROR] proc stst read error(%s) \n", err.Error())
		return
	}

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if fields[0] == "cpu" {
			numFields := len(fields)
			for i := 1; i < numFields; i++ {
				cpu2, _ := strconv.Atoi(fields[i])
				cpu := uint64(cpu2)
				//lprintf(4, "[INFO] stat cpu(%d) = (%d) \n", i, cpu)
				total = total + cpu

				if i == 1 {
					user = cpu
				} else if i == 4 {
					return
				}
			}
			return
		}
	}
	return
}
*/

// ps -eo user,pid,ppid,rss,size,vsize,pmem,pcpu,time,cmd --sort -rss | head -n 11
// return mem free, mem total
/*
func GetMEM() (free, total int) {

	var memTotal, memFree, swapTotal, swapFree int

	contents, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		lprintf(1, "[ERROR] proc meminfo read error(%s) \n", err.Error())
		return
	}

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)

		if fields[0] == "MemTotal:" {
			memTotal, _ = strconv.Atoi(fields[1])
		} else if fields[0] == "MemFree:" {
			memFree, _ = strconv.Atoi(fields[1])
		} else if fields[0] == "SwapTotal:" {
			swapTotal, _ = strconv.Atoi(fields[1])
		} else if fields[0] == "SwapFree:" {
			swapFree, _ = strconv.Atoi(fields[1])
		}

		if memTotal > 0 && memFree > 0 && swapTotal > 0 && swapFree > 0 {
			free = memFree + swapFree
			total = memTotal + swapTotal
			return
		}
	}
	return
}
*/

// return nic total mbps/sec
// 1 mbps/sec 122 kb/sec 122000 byte/sec

// 1기가 랜 1Gbps = 100MB/s 내외 102400KB/s byte
/*
func GetNET() (mbps uint64) {

	contents, err := ioutil.ReadFile("/proc/net/dev")
	if err != nil {
		lprintf(1, "[ERROR] proc net dev read error(%s) \n", err.Error())
		return
	}

	lines := strings.Split(string(contents), "\n")
	for i := 2; i < len(lines); i++ {
		fields := strings.Fields(lines[i])

		if len(lines[i]) == 0 {
			continue
		}

		value, err := strconv.ParseUint(fields[1], 0, 64)
		if err != nil {
			lprintf(1, "[ERROR] strconv parseUint(%s) error(%s) \n", fields[0], err.Error())
			continue
		}

		lprintf(1, "[INFO] proc sockstat read error(%s) \n", err.Error())

		mbps += value
	}

	return
}
/*

// return tcp session count
/*
func GetTCP() (tcp int) {

	contents, err := ioutil.ReadFile("/proc/net/sockstat")
	if err != nil {
		lprintf(1, "[ERROR] proc sockstat read error(%s) \n", err.Error())
		return
	}

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)

		if fields[0] == "TCP:" {
			tcp, _ = strconv.Atoi(fields[2])
			return
		}
	}
	return
}
*/

// run bash cmd return value
func RunCmd_S(cmd string) (int, string) {

	lprintf(4, "[INFO] run cmd %s \n", cmd)

	list, err := exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil {
		lprintf(1, "[ERROR] run cmd(%s) output fail(%s) \n", cmd, err.Error())
		return FAIL, ""
	}

	outData := strings.TrimSpace(string(list))

	return SUCCESS, outData

}

func RunCmd_S2(cmd string) (int, string) {

	list, err := exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil {
		return FAIL, ""
	}

	outData := strings.TrimSpace(string(list))

	return SUCCESS, outData

}

// run bash cmd return none
func RunCmd_N(cmd string) int {

	lprintf(4, "[INFO] run cmd %s \n", cmd)

	exeCmd := exec.Command("/bin/bash", "-c", cmd)
	err := exeCmd.Run()
	if err != nil {
		lprintf(1, "[ERROR] run cmd fail(%s) \n", err.Error())
		return FAIL
	}

	return SUCCESS

}

func PrintAgent() {

	lprintf(4, "========== print Agent info ==========\n")

	lprintf(4, "[INFO] uuid = (%s)\n", Agent_t.uuId)
	lprintf(4, "[INFO] osName = (%s)\n", Agent_t.osName)
	lprintf(4, "[INFO] osBit = (%s)\n", Agent_t.osBit)

	lprintf(4, "[INFO] plgId = (%s)\n", Agent_t.plgId)
	lprintf(4, "[INFO] plgVer = (%d)\n", Agent_t.plgVer)
	lprintf(4, "[INFO] proId = (%s)\n", Agent_t.proId)
	lprintf(4, "[INFO] proVer = (%d)\n", Agent_t.proVer)

	lprintf(4, "[INFO] reportInterval = (%d)\n", Agent_t.reportInterval)
	lprintf(4, "[INFO] getIp = (%s)\n", Agent_t.getIp)
	lprintf(4, "[INFO] fromMail = (%s)\n", Agent_t.fromMail)
	lprintf(4, "[INFO] toMail = (%s)\n", Agent_t.toMail)

	for i := 0; i < len(Agent_t.ispinfo_t); i++ {
		lprintf(4, "[INFO] isp info = (%s)(%s)\n", Agent_t.ispinfo_t[i].domain, Agent_t.ispinfo_t[i].alias)
	}

	PrintNic()

	lprintf(4, "=================================\n")
}

func PrintNic() {

	for i := 0; i < len(Agent_t.nic_t); i++ {

		lprintf(4, "========== nic info ==========\n")

		lprintf(4, "[INFO] nicName = (%s)\n", Agent_t.nic_t[i].nicName)
		lprintf(4, "[INFO] nicMac = (%s)\n", Agent_t.nic_t[i].nicMac)
		lprintf(4, "[INFO] nicIp = (%s)\n", Agent_t.nic_t[i].nicIp)
		lprintf(4, "[INFO] nicPubIp = (%s)\n", Agent_t.nic_t[i].nicPubIp)
		lprintf(4, "[INFO] nicIpv = (%d)\n", Agent_t.nic_t[i].nicIpv)
		lprintf(4, "[INFO] nicAdmin = (%d)\n", Agent_t.nic_t[i].nicAdmin)
		lprintf(4, "[INFO] nicLink = (%d)\n", Agent_t.nic_t[i].nicLink)
		lprintf(4, "[INFO] nicUse = (%d)\n", Agent_t.nic_t[i].nicUse)

		for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
			PrintPlugin(Agent_t.nic_t[i].plugin_t[j])
		}
	}
}

func PrintPlugin(plugin_t plugin_s) {

	lprintf(4, "========== plugin info ==========\n")

	lprintf(4, "[INFO] plgName = (%s)\n", plugin_t.plgName)
	lprintf(4, "[INFO] plgId = (%s)\n", plugin_t.plgId)
	lprintf(4, "[INFO] plgVer = (%d)\n", plugin_t.plgVer)
	lprintf(4, "[INFO] proId = (%s)\n", plugin_t.proId)
	lprintf(4, "[INFO] proVer = (%d)\n", plugin_t.proVer)
	lprintf(4, "[INFO] plgState = (%d)\n", plugin_t.plgState)
}

func SendMail(nic nic_s, plg plugin_s) int {

	if len(Agent_t.toMail) == 0 {
		lprintf(1, "[FAIL] not setting mail info in conf, not send mail \n")
		return FAIL
	}

	from := Agent_t.fromMail
	to := Agent_t.toMail

	msg := "Subject: 플러그인 상태 알림 메일 \r\n" +
		"Content-Type: text/plain;charset=utf-8 \r\n" +
		"Content-Language: ko \r\n\r\n" +

		"Plugin ID(" + plg.plgId + ") : Name(" + plg.plgName + ") was dead \r\n" +
		"- Server IP is " + nic.nicPubIp + "(" + nic.nicName + ") \r\n" +
		"Please check the Plugin \r\n" +
		"\r\n\r\n" +

		"This mail was sent by smartagent \r\n" +
		"This is an outging mail-addr only, please do not reply. \r\n" +
		"This is PLUS Service"

	//FROM_MAIL = sender@innogs.com

	sendMail := exec.Command("sendmail", "-f", from, to)
	stdin, err := sendMail.StdinPipe()
	if err != nil {
		lprintf(1, "[ERROR] send mail pipe fail(%s) \n", err.Error())
		return FAIL
	}

	sendMail.Start()
	stdin.Write([]byte(msg))
	stdin.Close()

	/*
		lprintf(4, "[INFO] SendMail to SLACK nic(%s), plg(%s) \n", nic.nicName, plg.plgName)

		msg := "{\"text\":" + "\"플러그인 상태 알림 메일 \n\n" +
			"Plugin ID(" + strconv.Itoa(plg.plgId) + ") : Name(" + plg.plgName + ") was dead \n" +
			"- Server IP is " + Agent_t.nic_t[1].nicPubIp + "(" + nic.nicName + ") \n" +
			"- Device ID is " + strconv.Itoa(Agent_t.deviceId) + "\n" +
			"Please check the Plugin \n" +
			"\n\n" +
			"This mail was sent by smartagent \n" +
			"This is an outging mail-addr only, please do  not reply. \n" +
			"This is PLUS Service.\"}"

		resp, err := http.Post(Agent_t.slack, "application/json", bytes.NewBuffer([]byte(msg)))
		if err != nil {
			lprintf(1, "[ERROR] SendMail to SLACK error(%s) \n", err.Error())
			return FAIL
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			lprintf(4, "[INFO] SLACK response msg(%s) \n", string(body))
		}
	*/

	return SUCCESS
}

func PlgStart(plg plugin_s) int {

	var cmd string

	if plg.plgName == "smartagent" {
		return SUCCESS
	} else if plg.plgName == "db" {

		cmd = "service mysql start"
		RunCmd_N(cmd)

		return SUCCESS
	}

	// startup.sh
	cmd = DEFAULT_PATH + plg.nicName + "/" + plg.plgName + PLUGIN_START + " " + DEFAULT_PATH + plg.nicName + "/" + plg.plgName

	lprintf(4, "[INFO] cmd(%s) run \n", cmd)
	if RunCmd_N(cmd) < 0 {
		lprintf(1, "[ERROR] plg start fail cmd(%s) \n", cmd)
		return FAIL
	}

	if plg.plgName == "smartidle" {

		//notiData := fmt.Sprintf("%s", Agent_t.uuId)
		//go notiMakeFile("UUID", "smartidle", notiData)

		// idle이 재기동 하면 spherer로 nginx conf를 요청 하고
		// nginx conf의 server ip 값을 agent에게 white list로 등록하라고 요청
		// white list에 server ip를 지속적으로 누적 할 수 없기에, idle 기동 시 기존 white list 목록의 act를 1 -> 0 으로 변경
		updateFW("WHITE_FW_TAB", "idle")
	}

	return SUCCESS
}

func PlgStop(plg plugin_s) int {

	var cmd string

	if plg.pId == 0 || plg.plgName == "smartagent" {
		return SUCCESS
	}

	lprintf(4, "[INFO] find process pid(%d), plugin name(%s) \n", plg.pId, plg.plgName)

	// stop.sh
	plgPath := DEFAULT_PATH + plg.nicName + "/" + plg.plgName
	cmd = plgPath + PLUGIN_STOP + " " + strconv.Itoa(plg.pId) + " " + plgPath
	lprintf(4, "[INFO] cmd(%s) run \n", cmd)
	if RunCmd_N(cmd) < 0 {
		lprintf(1, "[ERROR] plg start fail cmd(%s) \n", cmd)
		return FAIL
	}

	return SUCCESS
}

func PlgDelete(plg plugin_s) int {

	var nicIndex int
	var plugin_sql_t plugin_sql

	plugin_sql_t.PluginId = plg.plgId
	plugin_sql_t.PluginNicName = plg.nicName

	// del sql
	if SqlDeletePlugin(plugin_sql_t) < 0 {
		lprintf(1, "[ERROR] sql plugin delete fail \n")
		return FAIL
	}

	// del agent list
	for i := 0; i < len(Agent_t.nic_t); i++ {
		if plg.nicName == Agent_t.nic_t[i].nicName {
			nicIndex = i
			break
		}
	}

	for j := 0; j < len(Agent_t.nic_t[nicIndex].plugin_t); j++ {
		if plg.plgId == Agent_t.nic_t[nicIndex].plugin_t[j].plgId {
			lprintf(4, "[INFO] delete plg in agent struct \n")
			Agent_t.nic_t[nicIndex].plugin_t = Agent_t.nic_t[nicIndex].plugin_t[:j+copy(Agent_t.nic_t[nicIndex].plugin_t[j:], Agent_t.nic_t[nicIndex].plugin_t[j+1:])]
			break
		}
	}

	// 삭제 명령 시 디렉토리는 삭제 안함
	// 재 설치 시 디렉토리 위에 덮는 방식

	/*delFile := DEFAULT_PATH + plg.nicName + "/" + plg.plgName
	lprintf(4, "[INFO] delete file(%s) start \n", delFile)
	FileDel(delFile)*/

	return SUCCESS

}

func certDelete(id string) int {

	// cert delete to sql
	if SqlStatementCert(DELETE, 0, id) < 0 {
		return FAIL
	}

	// cert delete to agent struct
	for i := 0; i < len(Agent_t.cert_t); i++ {
		if id == Agent_t.cert_t[i].certId {
			lprintf(4, "[INFO] delete cert(%s) in agent struct \n", id)
			Agent_t.cert_t = Agent_t.cert_t[:i+copy(Agent_t.cert_t[i:], Agent_t.cert_t[i+1:])]
			break
		}
	}

	return SUCCESS

}

// find pluginlist plugin
func FindPlg(plgId string) (int, plugin_s) {

	var plugin_t plugin_s

	for i := 0; i < len(Agent_t.nic_t); i++ {
		for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {

			if Agent_t.nic_t[i].plugin_t[j].plgId == plgId {

				lprintf(4, "[INFO] find plugin in agent struct plgid(%s) \n", plgId)

				return SUCCESS, Agent_t.nic_t[i].plugin_t[j]
			}
		}
	}
	return FAIL, plugin_t
}

// find pluginlist plugin
func FindPlgNic(NicName string, plgName string) (int, plugin_s) {

	var plugin_t plugin_s

	for i := 0; i < len(Agent_t.nic_t); i++ {

		if Agent_t.nic_t[i].nicName == NicName {
			for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
				if Agent_t.nic_t[i].plugin_t[j].plgName == plgName {
					lprintf(4, "[INFO] find plugin in agent struct NicName(%s), plgName(%s) \n", NicName, plgName)
					return SUCCESS, Agent_t.nic_t[i].plugin_t[j]
				}
			}
		}
	}

	//lprintf(1, "[ERROR] find plugin fail in agent struct NicName(%s), plgName(%s) \n", NicName, plgName)
	return FAIL, plugin_t
}

func FindPlgName(plgName string) bool {

	for i := 0; i < len(Agent_t.nic_t); i++ {
		for j := 0; j < len(Agent_t.nic_t[i].plugin_t); j++ {
			if Agent_t.nic_t[i].plugin_t[j].plgName == plgName {
				return true
			}
		}
	}

	return false
}

func BakToTmp(nicName, fileName string) int {

	err := os.Rename(SMARTAGENT_BAK+"/"+nicName+"/"+fileName, SMARTAGENT_TMP+"/"+fileName)
	if err != nil {
		lprintf(1, "[ERROR] plg remove fail(%s) \n", err.Error())
		return FAIL
	}

	return SUCCESS
}

// tmp dir plugin delete
func TmpToBak(nicName, fileName string, flag int) int {

	backName := fileName

	if MakeDir(SMARTAGENT_BAK+"/"+nicName) < 0 {
		lprintf(1, "[ERROR] make dir fail(%s) \n", SMARTAGENT_BAK+"/"+nicName)
		return FAIL
	}

	if flag == ST_PLUGIN {
		buff := strings.Split(fileName, "-")
		backName = buff[0] + ".tar"
	}

	err := os.Rename(SMARTAGENT_TMP+"/"+fileName, SMARTAGENT_BAK+"/"+nicName+"/"+backName)
	if err != nil {
		lprintf(1, "[ERROR] plg remove fail(%s) \n", err.Error())
		return FAIL
	}

	return SUCCESS
}

//gzip 풀기
func GzipDecompress(gzipName string) (int, string) {

	var tarName string

	reader, err := os.Open(SMARTAGENT_TMP + "/" + gzipName)
	if err != nil {
		lprintf(1, "[ERROR] gzip reader(%s) open fail(%s) \n", gzipName, err.Error())
		return FAIL, tarName
	}
	defer reader.Close()

	archive, err := gzip.NewReader(reader)
	if err != nil {
		lprintf(1, "[ERROR] gzip new reader fail(%s) \n", err.Error())
		return FAIL, tarName
	}
	defer archive.Close()

	tarName = filepath.Join(SMARTAGENT_TMP, archive.Name)
	writer, err := os.Create(tarName)
	if err != nil {
		lprintf(1, "[ERROR] tar(%s) create fail(%s) \n", tarName, err.Error())
		return FAIL, tarName
	}
	defer writer.Close()

	_, err = io.Copy(writer, archive)
	if err != nil {
		lprintf(1, "[ERROR] gzip copy fail(%s) \n", err.Error())
		return FAIL, tarName
	}

	//gzip del
	FileDel(tarName)

	return SUCCESS, archive.Name

}

// tar 압축풀기
func TarDeCompress(nicName, tarName string) int {

	reader, err := os.Open(SMARTAGENT_TMP + "/" + tarName)
	if err != nil {
		lprintf(1, "[ERROR] tar reader(%s) open fail(%s) \n", tarName, err.Error())
		return FAIL
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}

		if err != nil {
			lprintf(1, "[ERROR] tar archive fail(%s) \n", err.Error())
			return FAIL
		}

		path := filepath.Join(DEFAULT_PATH+nicName, hdr.Name)
		lprintf(4, "[INFO] Contents of(%s), path(%s) \n", hdr.Name, path)
		info := hdr.FileInfo()

		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				lprintf(1, "[ERROR] make dir(%s) fail(%s) \n", path, err.Error())
				//return FAIL
			}
			continue
		}

		dst, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			lprintf(1, "[ERROR] tar dst(%s) open fail(%s) \n", nicName, err.Error())
			continue
		}
		defer dst.Close()

		if _, err = io.Copy(dst, tr); err != nil {
			lprintf(1, "[ERROR] tar copy fail(%s) \n", err.Error())
			continue
		}
	}

	return SUCCESS

}

// conf copy right dir
func ConfCopy(nicName, plgName, fileName string) int {

	fiPath := SMARTAGENT_TMP + "/" + fileName
	foPath := DEFAULT_PATH + nicName + "/" + plgName + "/conf/" + fileName

	fi, err := os.Open(fiPath)
	if err != nil {
		lprintf(1, "[ERROR] file(%s) open fail(%s) \n", fiPath, err.Error())
	}
	defer fi.Close()

	fis, _ := fi.Stat()
	if fis.Size() == 0 {
		lprintf(1, "[ERROR] file(%s) size 0", fiPath)
		return FAIL
	}

	fo, err := os.OpenFile(foPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		lprintf(1, "[ERROR] file(%s) open fail(%s) \n", foPath, err.Error())
	}
	defer fo.Close()

	if _, err = io.Copy(fo, fi); err != nil {
		lprintf(1, "[ERROR] tar copy fail(%s) \n", err.Error())
		return FAIL
	}

	return SUCCESS
}

// conf move right dir
func ConfBack(plgName, nicName, fileName string) int {

	err := os.Rename(SMARTAGENT_BAK+"/"+nicName+"/"+fileName, DEFAULT_PATH+nicName+"/"+plgName+"/conf/"+fileName)
	if err != nil {
		lprintf(1, "[ERROR] conf move fail(%s) \n", err.Error())
		return FAIL
	}

	return SUCCESS
}

// dir make
func MakeDir(dirPath string) int {

	if FileExist(dirPath) {
		return SUCCESS
	}
	// file mode is drwxr-x---
	if err := os.MkdirAll(dirPath, 0750); err != nil {
		lprintf(1, "[ERROR] dir make fail(%s) \n", dirPath)
		return FAIL
	}
	return SUCCESS
}

// op is download file info
func DownFile(id string, ver, op int) (int, string) {

	var fileName, filePath string
	fqdn := fmt.Sprintf("smartstation/getpkg?ftype=%d&uuid=%s&id=%s&ver=%d&sphereuuid=%s", op, Agent_t.uuId, id, ver, Agent_t.rsphereUUID)
	lprintf(4, "[INFO] cls http req fqdn(%s) \n", fqdn)

	resp, err := cls.HttpSend(cls.TCP_STATION, "GET", fqdn, true)
	if err != nil {
		lprintf(1, "[ERROR] cls HttpSend fail(%s) \n", err.Error())
		return FAIL, fileName
	}
	defer resp.Body.Close()

	fileName = resp.Header.Get("File-Name")
	lprintf(4, "[INFO] station get file name(%s) \n", fileName)

	if op == ST_PLUGIN || op == ST_PROFILE {
		filePath = SMARTAGENT_TMP + "/" + fileName
	} else {
		filePath = SMARTAGENT_CERT + "/" + fileName
	}

	lprintf(4, "[INFO] create file path(%s) \n", filePath)
	input, err := os.Create(filePath)
	if err != nil {
		lprintf(1, "[ERROR] file create fail(%s) \n", filePath)
		return FAIL, fileName
	}
	defer input.Close()

	if _, err := io.Copy(input, resp.Body); err != nil {
		lprintf(1, "[ERROR] io copy fail (%s)\n", err.Error())
		return FAIL, fileName
	}

	return SUCCESS, fileName
}

// 파일 존재여부 확인
func FileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	return true
}

// file path delete
func FileDel(filePath string) int {
	err := os.RemoveAll(filePath)
	if err != nil {
		lprintf(1, "[ERROR] file path remove error (%s) \n", err.Error())
		return FAIL
	}

	return SUCCESS
}

func getIdleCinfo(cIp, port string) string {

	addrs := fmt.Sprintf("http://%s:%s/clientInfo", Agent_t.nic_t[1].nicIp, port)

	lprintf(4, "[INFP] get idle fqdn(%s) \n", addrs)

	req, err := http.NewRequest("GET", addrs, bytes.NewBuffer([]byte(cIp)))
	if err != nil {
		lprintf(1, "[ERROR] http new request err(%s) \n", err.Error())
		return "NULL"
	}

	req.Header.Set("Connection", "close")
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "NULL"
	}
	defer resp.Body.Close()

	d, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "NULL"
	}

	return string(d)
}
