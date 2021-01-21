package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"charlie/i0.0.2/cls"
)

type XmlMatch struct {
	RuleId        int    `xml:"ruleid"`        // 1
	Direction     string `xml:"direction"`     // I,O (imput, output)
	StartTime     uint32 `xml:"starttime"`     // 0
	EndTime       uint32 `xml:"endtime"`       // 0
	SourceIp      string `xml:"sourceip"`      // 192.168.16.61/23
	DestinationIp string `xml:"destinationip"` // 0
	Protocol      string `xml:"protocol"`      // TCP
	PortNum       string `xml:"portnum"`       // 8800
	Action        string `xml:"action"`        // A,D (accept, drop)
	Activation    uint8  `xml:"activation"`    // 1,0 (active, not active)
	Priority      int    `xml:"priority"`      // 우선순위
}

type XmlRule struct {
	DeviceId string     `xml:"device_id"`
	FireVer  int        `xml:"fire_ver"`
	Match    []XmlMatch `xml:"match"`
}

type DeviceRule struct {
	// debug 용
	stime    [22]byte // 변환필요
	etime    [22]byte
	src_ip   [40]byte // -->uint32_t로 변경, cnt로 갯수 넣음
	dst_ip   [40]byte
	port_num [12]byte // debug - finish

	list       uint8
	start      uint8
	rule_id    uint16
	direction  uint8 //I,O
	pt         uint8 // POROTOCOL
	action     uint8
	activation uint8
	priority   uint16 // 우선순위

	fport uint16 // start port
	lport uint16 // last port
	dummy uint16 // last port

	istime uint32
	ietime uint32
	saddr  uint32 /* ip address */
	daddr  uint32 /* ip address */

	daddr_cnt uint16
	saddr_cnt uint16
}

type DeviceFW struct {
	deviceId [1024]byte
	rule_cnt int
	rule     [4096]DeviceRule
}

// ip reverse for device
func inet_aton(ip net.IP) (ip_int uint32) {
	ip_byte := ip.To4()
	i := len(ip_byte) - 1
	for ; i >= 0; i-- {
		ip_int |= uint32(ip_byte[i])
		if i > 0 {
			ip_int <<= 8
		}
	}
	return
}

func inet_mask(ips string) (uint32, uint16) {
	var cnt uint16
	ip := strings.Split(ips, "/")
	lprintf(4, "[INFO] inet_mask ips (%s) \n", ips)
	lprintf(4, "[INFO] inet_mask ip (%s) \n", ip)
	if len(ip) == 1 {
		return inet_aton(net.ParseIP(ip[0])), uint16(1)
	}

	sb, err := strconv.Atoi(ip[1])
	if err != nil {
		sb = 32
	}

	cnt = uint16(1)
	for i := 0; i < 32-sb; i++ {
		cnt = uint16(2) * cnt
	}
	cnt = cnt - uint16(1) // broad cast ip

	// This mask corresponds to a /24 subnet for IPv4.
	ipv4Addr := net.ParseIP(ip[0])
	lprintf(4, "[INFO] inet_mask ipv4Addr (%s) \n", ipv4Addr.String())
	lprintf(4, "[INFO] inet_mask cnt (%d) \n", cnt)

	ipv4Mask := net.CIDRMask(sb, 32)
	return inet_aton(ipv4Addr.Mask(ipv4Mask)), cnt
}

func setDeviceFromRule(devFw *DeviceFW, rule XmlMatch, i int) int {

	devFw.rule[i].start = 'N'
	devFw.rule[i].direction = uint8(rule.Direction[0])

	// time -> format change string -> uint32
	/*
		copy(devFw.rule[i].stime[:], rule.StartTime)
		layout := "2006-01-02 15:04:05"
		if rule.StartTime[0] == 'A' || rule.StartTime[0] == '0' {
			devFw.rule[i].istime = 0
		} else {
			t, err := time.Parse(layout, rule.StartTime)
			if err != nil {
				lprintf(1, "[ERROR] xml time formant error (%s)\n", rule.StartTime)
				return FAIL
			}
			devFw.rule[i].istime = uint32(t.Unix())
		}

		copy(devFw.rule[i].etime[:], rule.EndTime)
		if rule.EndTime[0] == 'A' || rule.EndTime[0] == '0' {
			devFw.rule[i].ietime = 0
		} else {
			t, err := time.Parse(layout, rule.EndTime)
			if err != nil {
				lprintf(1, "[ERROR] xml time formant error (%s)\n", rule.EndTime)
				return FAIL
			}
			devFw.rule[i].ietime = uint32(t.Unix())
		}
	*/

	devFw.rule[i].istime = rule.StartTime
	devFw.rule[i].ietime = rule.EndTime
	lprintf(4, "[INFO] xml stime(%d) - etime(%d)\n", devFw.rule[i].istime, devFw.rule[i].ietime)

	// ip
	copy(devFw.rule[i].src_ip[:], rule.SourceIp)
	if rule.SourceIp[0] == 'A' || rule.SourceIp[0] == '0' {
		devFw.rule[i].saddr = 0
		devFw.rule[i].saddr_cnt = 1
	} else {
		devFw.rule[i].saddr, devFw.rule[i].saddr_cnt = inet_mask(rule.SourceIp)
	}

	copy(devFw.rule[i].dst_ip[:], rule.DestinationIp)
	if rule.DestinationIp[0] == 'A' || rule.DestinationIp[0] == '0' {
		devFw.rule[i].daddr = 0
		devFw.rule[i].daddr_cnt = 1
	} else {
		devFw.rule[i].daddr, devFw.rule[i].daddr_cnt = inet_mask(rule.DestinationIp)
	}
	lprintf(4, "[INFO] xml saddr(%d) daddr (%d)\n", devFw.rule[i].saddr, devFw.rule[i].daddr)

	// protocol
	if rule.Protocol == "ANY" || rule.Protocol == "0" {
		devFw.rule[i].pt = uint8(0)
	} else if rule.Protocol == "TCP" {
		devFw.rule[i].pt = uint8(6)
	} else if rule.Protocol == "UDP" {
		devFw.rule[i].pt = uint8(17)
	} else if rule.Protocol == "ICMP" {
		devFw.rule[i].pt = uint8(1)
	} else {
		lprintf(1, "[ERROR] protocol formant error (%s)\n", rule.Protocol)
		return FAIL
	}

	// port
	copy(devFw.rule[i].port_num[:], rule.PortNum)
	if devFw.rule[i].port_num[0] == '0' {
		devFw.rule[i].fport = 0
		devFw.rule[i].lport = 0
	} else {
		ports := strings.Split(rule.PortNum, "-")
		fport, _ := strconv.Atoi(ports[0])
		if len(ports) == 1 {
			devFw.rule[i].fport = uint16(fport)
			devFw.rule[i].lport = devFw.rule[i].fport
		} else {
			lport, _ := strconv.Atoi(ports[1])
			devFw.rule[i].fport = uint16(fport)
			devFw.rule[i].lport = uint16(lport)
		}
	}
	lprintf(4, "[INFO] xml fport(%d) lport (%d)\n", devFw.rule[i].fport, devFw.rule[i].lport)

	// action & activation
	devFw.rule[i].action = rule.Action[0]
	devFw.rule[i].activation = uint8(rule.Activation)

	// make reverse rule
	devFw.rule[i+1] = devFw.rule[i]
	devFw.rule[i+1].saddr = devFw.rule[i].daddr
	devFw.rule[i+1].daddr = devFw.rule[i].saddr
	if devFw.rule[i+1].direction == 'I' {
		devFw.rule[i+1].direction = 'O'
	} else {
		devFw.rule[i+1].direction = 'I'
	}
	//2019.06.26 cnt, pt 추가 dhjo
	devFw.rule[i+1].src_ip = devFw.rule[i].dst_ip
	devFw.rule[i+1].saddr_cnt = devFw.rule[i].daddr_cnt
	devFw.rule[i+1].dst_ip = devFw.rule[i].src_ip
	devFw.rule[i+1].daddr_cnt = devFw.rule[i].saddr_cnt
	devFw.rule[i+1].pt += uint8(200)

	return SUCCESS
}

func writeDevice(devFw *DeviceFW, count int) int {

	if count == 0 {
		return FAIL
	}

	devFw.rule_cnt = count
	if devFw.rule_cnt == 0 {
		devFw.rule[0].start = '0'
		devFw.rule_cnt = 1
	} else if devFw.rule_cnt == 1 {
		devFw.rule[0].start = '1'
	} else {
		devFw.rule[0].start = 'S'
		devFw.rule[count-1].start = 'E'
	}

	fd, err := os.OpenFile("/dev/smartfw", os.O_RDWR, 0777)
	if err != nil {
		lprintf(1, "[FAIL] read firewall device module")
		return FAIL
	}
	defer fd.Close()

	for k := 0; k < count; k++ {
		buf := &bytes.Buffer{}
		err := binary.Write(buf, binary.LittleEndian, devFw.rule[k])
		if err == nil {
			lprintf(4, "[INFO] write firewall device module (%v) \n", buf.Bytes())
			fd.Write(buf.Bytes())
		}
	}
	return SUCCESS
}

// flood rull to device
func floodToDevice() (int, int) {

	var devFw DeviceFW
	var flood, floodCnt, block int
	var rPeriod, rSize, rBlock int
	var version int

	query := "SELECT RULE_VERSION, BLOCK_PERIOD, FLOOD_CNT, FLOOD_PERIOD, RBLOCK_PERIOD, READ_SIZE, READ_PERIOD FROM FLOOD_FW_TAB WHERE ACT ='1'"
	lprintf(4, "[IFNO] select query : %s\n", query)

	rows, err := cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL, 0
	}
	defer rows.Close()

	if rows.Next() { // only 1 row
		if err = rows.Scan(&version, &block, &floodCnt, &flood, &rBlock, &rSize, &rPeriod); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return 0, FAIL
		}
		devFw.rule[0].list = 'F'
		devFw.rule[0].start = 'N'
		devFw.rule[0].rule_id = uint16(block)
		devFw.rule[0].fport = uint16(floodCnt)
		devFw.rule[0].lport = uint16(flood)

	} else {
		return FAIL, 0
	}

	/*
		if Agent_t.siteId != 0 && Agent_t.manager == 0 {
			data := fmt.Sprintf("%d^%d^%d", rPeriod, rSize, rBlock)
			go notiMakeFile("SLOWREAD", []byte(data))
		}
	*/

	if FindPlgName("smartidle") {
		data := fmt.Sprintf("%d^%d^%d", rPeriod, rSize, rBlock)
		go notiMakeFile("SLOWREAD", "smartidle", data)
	}

	// write firewall device
	FloodBlockTime = uint32(block)
	ReadBlockTime = uint32(rBlock)
	return writeDevice(&devFw, 1), version
}

// white, black rull to device
func sqlToDevice() int {
	var devFw DeviceFW

	query := "SELECT DIR, SIP, DIP, PROTOCOL, PORT, STIME, ETIME FROM WHITE_FW_TAB WHERE ACT ='1' AND (ETIME > '지금' OR ETIME = 0)"
	lprintf(4, "[IFNO] select query : %s\n", query)

	rows, err := cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL
	}

	i := 0
	for rows.Next() {
		var rule XmlMatch
		if err = rows.Scan(&rule.Direction, &rule.SourceIp, &rule.DestinationIp, &rule.Protocol, &rule.PortNum, &rule.StartTime, &rule.EndTime); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return FAIL
		}
		devFw.rule[i].list = 'L'
		devFw.rule[i].rule_id = uint16(i)
		devFw.rule[i].priority = uint16(i)
		rule.Activation = 1
		rule.Action = "A"

		if setDeviceFromRule(&devFw, rule, i) == FAIL {
			lprintf(1, "[ERROR] rule parse fail\n")
			return FAIL
		}
		i = i + 2
	}
	rows.Close()

	query = "SELECT DIR, SIP, DIP, PROTOCOL, PORT, STIME, ETIME FROM BLACK_FW_TAB WHERE ACT ='1' AND (ETIME > '지금' OR ETIME = 0)"
	lprintf(4, "[IFNO] select query : %s\n", query)

	rows, err = cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL
	}

	for rows.Next() {
		var rule XmlMatch
		if err = rows.Scan(&rule.Direction, &rule.SourceIp, &rule.DestinationIp, &rule.Protocol, &rule.PortNum, &rule.StartTime, &rule.EndTime); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return FAIL
		}
		devFw.rule[i].list = 'L'
		devFw.rule[i].rule_id = uint16(i)
		devFw.rule[i].priority = uint16(i)
		rule.Activation = 1
		rule.Action = "D"

		if setDeviceFromRule(&devFw, rule, i) == FAIL {
			lprintf(1, "[ERROR] rule parse fail\n")
			return FAIL
		}
		i = i + 2
	}
	rows.Close()

	return writeDevice(&devFw, i)
}

// user rull to device
func xmlQueryToDevice() (int, int) {

	var xmlData string
	query := "SELECT RULE_XML FROM RULE_FW_TAB WHERE ACT ='1';"
	lprintf(4, "[IFNO] select query : %s\n", query)

	rows, err := cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL, 0
	}
	defer rows.Close()

	if rows.Next() {
		if err = rows.Scan(&xmlData); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return FAIL, 0
		}
	} else {
		return FAIL, 0
	}

	return xmlToDevice(xmlData)
}

func xmlToDevice(xmlData string) (int, int) {

	var xmlRule XmlRule
	var devFw DeviceFW

	err := xml.Unmarshal([]byte(xmlData), &xmlRule)
	if err != nil {
		lprintf(1, "[ERROR] xml unmarshal error(%s)\n", err.Error())
		return FAIL, 0
	}

	if len(xmlRule.Match) == 0 {
		return FAIL, 0
	}

	i := 0
	for _, rule := range xmlRule.Match {
		devFw.rule[i].rule_id = uint16(rule.RuleId) + uint16(10000)
		devFw.rule[i].priority = uint16(rule.Priority) + uint16(10000)

		if setDeviceFromRule(&devFw, rule, i) == FAIL {
			lprintf(1, "[ERROR] rule parse fail\n")
			return FAIL, 0
		}
		i = i + 2
	}

	return writeDevice(&devFw, i), xmlRule.FireVer
}
