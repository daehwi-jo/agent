package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"charlie/i0.0.2/cls"
)

var FloodBlockTime, ReadBlockTime uint32

func initFirewall() int {
	/*fd, err := os.OpenFile("/dev/smartfw", os.O_RDWR, 0777)
	if err != nil {
		lprintf(1, "[FAIL] read firewall device module")
		return FAIL
	}
	fd.Close()*/

	lprintf(4, "[INFO] make firewall table \n")
	query := "CREATE TABLE IF NOT EXISTS WHITE_FW_TAB (DIV CHAR (2), DIR CHAR(2), SIP CHAR(32), DIP CHAR(32), STIME INTEGER, ETIME INTEGER, PROTOCOL CHAR(10), PORT CHAR(10), ACT CHAR(2), REASON CHAR(100), PRIMARY KEY(DIR, SIP, DIP, PROTOCOL, PORT, STIME, ETIME));"
	lprintf(4, "[INFO] query : %s\n", query)
	if CreateReqTableV(query) < 0 {
		lprintf(1, "[ERROR] cert_tab WHITE table make error \n")
	}

	query = "CREATE TABLE IF NOT EXISTS BLACK_FW_TAB (DIV CHAR (2), DIR CHAR(2), SIP CHAR(32), DIP CHAR(32), STIME INTEGER, ETIME INTEGER, PROTOCOL CHAR(10), PORT CHAR(10), ACT CHAR(2), REASON CHAR(100), PRIMARY KEY(DIR, SIP, DIP, PROTOCOL, PORT, STIME, ETIME));"
	lprintf(4, "[INFO] query : %s\n", query)
	if CreateReqTableV(query) < 0 {
		lprintf(1, "[ERROR] cert_tab BLACK table make error \n")
	}

	query = "CREATE TABLE IF NOT EXISTS FLOOD_FW_TAB (RULE_VERSION INTEGER, BLOCK_PERIOD INTEGER, FLOOD_CNT INTEGER, FLOOD_PERIOD INTEGER, RBLOCK_PERIOD INTEGER, READ_SIZE INTEGER, READ_PERIOD INTEGER, ACT CHAR(2), PRIMARY KEY(ACT));"
	lprintf(4, "[INFO] query : %s\n", query)
	if CreateReqTableV(query) < 0 {
		lprintf(1, "[ERROR] cert_tab FLOOD table make error \n")
	}

	query = "CREATE TABLE IF NOT EXISTS RULE_FW_TAB (RULE_XML CHAR (819000), ACT CHAR(2), PRIMARY KEY(ACT));"
	lprintf(4, "[INFO] query : %s\n", query)
	if CreateReqTableV(query) < 0 {
		lprintf(1, "[ERROR] cert_tab FLOOD table make error \n")
	}

	go readDevice()

	return SUCCESS
}

// update firewall act 0
func updateFW(tblName, div string) int {
	query := "UPDATE " + tblName + " SET ACT = ? WHERE DIV = ?"
	//lprintf(4, "[INFO] update query : %s -> sip (%s), tblName (%s) \n", query, sip, tblName)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()
	_, err = statement.Exec("0", div)
	if err != nil {
		lprintf(1, "[ERROR] sql update exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// insert firewall(white, black) list
func insertFW(tblName, div, dir, sip, dip string, stime, etime uint32, protocol, port, reason string) int {
	query := "INSERT INTO " + tblName + " (DIV, DIR, SIP, DIP, STIME, ETIME, PROTOCOL, PORT, ACT, REASON) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	lprintf(4, "[INFO] insert query : %s -> sip (%s), tblName (%s) \n", query, sip, tblName)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()
	_, err = statement.Exec(div, dir, sip, dip, stime, etime, protocol, port, "1", reason)
	if err != nil {
		lprintf(1, "[ERROR] sql insert exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// insert or replace firewall(white, black) list
func insertReplaceFW(tblName, div, dir, sip, dip string, stime, etime uint32, protocol, port, reason string) int {
	query := "INSERT OR REPLACE INTO " + tblName + " (DIV, DIR, SIP, DIP, STIME, ETIME, PROTOCOL, PORT, ACT, REASON) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	lprintf(4, "[INFO] insert query : %s -> sip (%s), tblName (%s) \n", query, sip, tblName)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()
	_, err = statement.Exec(div, dir, sip, dip, stime, etime, protocol, port, "1", reason)
	if err != nil {
		lprintf(1, "[ERROR] sql insert exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// response delBlack
func delBlack(ip string) ([]string, int) {

	var query string
	var selctIp []string

	if len(ip) > 0 {
		query = "DELETE FROM BLACK_FW_TAB WHERE SIP = ?"
	} else {
		query = "SELECT SIP FROM BLACK_FW_TAB WHERE ACT = 0"
	}

	lprintf(4, "[INFO] query : %s \n", query)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return selctIp, FAIL
	}
	defer statement.Close()

	if len(ip) > 0 {
		_, err = statement.Exec(ip)
		if err != nil {
			lprintf(1, "[ERROR] sql delete exec error : %s\n", err.Error())
			return selctIp, FAIL
		}
	} else {
		rows, err := statement.Query()
		if err != nil {
			lprintf(1, "[ERROR] sql select exec error : %s\n", err.Error())
			return selctIp, FAIL
		}

		if rows.NextResultSet() {
			for rows.Next() {
				var sIp string
				if err := rows.Scan(&sIp); err != nil {
					lprintf(1, "[ERROR] scan error : %s\n", err)
					return selctIp, FAIL
				}
				selctIp = append(selctIp, sIp)
			}

		}
	}

	lprintf(4, "[INFO] statement query finished \n")
	return selctIp, SUCCESS

}

// delete firewall(white, black) list
func deleteFW(tblName, dir, sip, port string, stime, etime uint32) int {
	//DIR, SIP, DIP, PROTOCOL, PORT, STIME, ETIME

	query := "DELETE FROM " + tblName + " WHERE DIR = ? AND SIP = ? AND PORT = ? AND STIME = ? AND ETIME = ?"
	lprintf(4, "[INFO] delete query : %s -> sip (%s), tblName (%s) \n", query, sip, tblName)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()

	_, err = statement.Exec(dir, sip, port, stime, etime)
	if err != nil {
		lprintf(1, "[ERROR] sql delete exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// insert firewall(user) list
func insertXML(xmlRule string) int {
	query := "INSERT OR REPLACE INTO RULE_FW_TAB (RULE_XML, ACT) VALUES (?, ?)"
	lprintf(4, "[INFO] insert or replace query xml (%s)\n", query)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()
	_, err = statement.Exec(xmlRule, "1")
	if err != nil {
		lprintf(1, "[ERROR] sql insert exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// insert Defence(flood) list
func insertDefence(version, fBlockTime, floodCnt, floodTime, rBlockTime, readSize, readTime int) int {
	query := "INSERT OR REPLACE INTO FLOOD_FW_TAB (RULE_VERSION, BLOCK_PERIOD, FLOOD_CNT, FLOOD_PERIOD, RBLOCK_PERIOD, READ_SIZE, READ_PERIOD, ACT) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
	lprintf(4, "[INFO] insert or replace query xml (%s)\n", query)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()
	_, err = statement.Exec(version, fBlockTime, floodCnt, floodTime, rBlockTime, readSize, readTime, "1")
	if err != nil {
		lprintf(1, "[ERROR] sql insert exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

/*
방화벽 모듈로 부터 악성 Client 정보를 올려 받는다.

과거
악성 Client를 Black List로 만들어 방화벽 모듈에게 rull 전달
해당 내용은 sphere 에게 보고

2020.09.15
악성 Client를 Black List로 바로 넣지 말고 sphere 에게만 보고
sphere의 판단을 통해 Black List rull 전달 예정
*/
func readDevice() int {

	for ; true; time.Sleep(3 * time.Second) {
		fd, err := os.OpenFile("/dev/smartfw", os.O_RDWR, 0777)
		if err != nil {
			//lprintf(1, "[FAIL] read firewall device module")
			continue
		}

		buf := make([]byte, 6)
		len, err := fd.Read(buf)
		if err != nil || len == 0 {
			//lprintf(1, "[FAIL] read nothing from device module (%s)", err)
			fd.Close()
			continue
		}

		for rlen := 0; err == nil && len < 6; len += rlen {
			rlen, err = fd.Read(buf[len:])
		}

		fd.Close()

		if err != nil {
			lprintf(1, "[FAIL] read nothing from device module (%s)", err)
			continue
		}

		lprintf(4, "[INFO] read flood info (%v) from device module", buf)

		//  insert Black list
		var reportJson reportfirewall
		//reportJson.DevID = Agent_t.deviceId
		reportJson.UuID = Agent_t.uuId
		reportJson.Command = 0
		reportJson.List = 1
		reportJson.Port = 0
		reportJson.Source = "smartfw"
		//reportJson.Ip = fmt.Sprintf("%d.%d.%d.%d", buf[3], buf[2], buf[1], buf[0])
		reportJson.Ip = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		reportJson.Time = uint32(time.Now().Unix())
		reportJson.Period = FloodBlockTime
		reportJson.Service = getIdleCinfo(reportJson.Ip, "18900")
		if buf[4] == 1 {
			reportJson.Reason = "SYNFLOOD"
		} else {
			reportJson.Reason = "LANDATTACK"
		}

		// 기본적으로 black list 내용은 방화벽에 넣지 않고 sphere에게 보고만 한다
		if Agent_t.defUse == YES {
			var startTime, endTime uint32
			if FloodBlockTime != 0 {
				startTime = reportJson.Time
				endTime = reportJson.Time + FloodBlockTime
			}

			if buf[4] == 1 {
				insertFW("BLACK_FW_TAB", "smartfw", "I", reportJson.Ip, "0", startTime, endTime, "0", "0", reportJson.Reason)
			} else {
				insertFW("BLACK_FW_TAB", "smartfw", "I", reportJson.Ip, "0", startTime, endTime, "0", "0", reportJson.Reason)
			}

			// apply device
			if sqlToDevice() == FAIL {
				lprintf(1, "[FAIL] sql inert error")
				continue
			}
		}

		// new sphere format
		var reportJson2 SetPlusAttackReportOneParam
		reportJson2.Uuid = Agent_t.uuId
		reportJson2.ReportReason = reportJson.Reason
		reportJson2.ClientIp = reportJson.Ip
		reportJson2.Fqdn = reportJson.Service

		// send Sphere to report
		reportByte, err := json.Marshal(reportJson2)
		if err != nil {
			lprintf(1, "[FAIL] json marshal error  (%s)", err)
			continue
		}

		resp, err := cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
		if err != nil {
			lprintf(1, "[ERROR] report firewall error(%s) \n", err.Error())
			cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
			return SUCCESS
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			lprintf(1, "[ERROR] report firewall statusCode(%d) \n", resp.StatusCode)
			cls.HttpSendJSON(cls.TCP_SPHERE, "GET", "smartagent/reportfirewall", reportByte, true)
		}

	}

	return SUCCESS
}

func plgToWhite(sphere, station string) {

	lprintf(4, "[INFO] white list write sphere(%s), station(%s) \n", sphere, station)

	if updateFW("WHITE_FW_TAB", "agent") < 0 {
		lprintf(1, "[FAIL] white list agent act set 0 fail \n")
	}

	spIp := strings.Split(sphere, "&")
	for i := 0; i < len(spIp); i++ {
		if insertReplaceFW("WHITE_FW_TAB", "agent", "I", spIp[i], "0", 0, 0, "TCP", "0", "Manager Node") < 0 {
			lprintf(1, "[FAIL] white list sql write fail, retry \n")

			if insertReplaceFW("WHITE_FW_TAB", "agent", "I", spIp[i], "0", 0, 0, "TCP", "0", "Manager Node") < 0 {
				lprintf(1, "[FAIL] white list sql write fail \n")
				continue
			}
		}
	}

	stIp := strings.Split(station, "&")
	for j := 0; j < len(stIp); j++ {
		if insertReplaceFW("WHITE_FW_TAB", "agent", "I", stIp[j], "0", 0, 0, "TCP", "0", "Manager Node") < 0 {
			lprintf(1, "[FAIL] white list sql write fail, retry \n")

			if insertReplaceFW("WHITE_FW_TAB", "agent", "I", stIp[j], "0", 0, 0, "TCP", "0", "Manager Node") < 0 {
				lprintf(1, "[FAIL] white list sql write fail \n")
				continue
			}
		}
	}

	if sqlToDevice() < 0 {
		lprintf(1, "[FAIL] sql to device fail, retry \n")
		sqlToDevice()
	}

}
