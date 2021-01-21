/*
	smartagent sql
*/

package main

import (
	"fmt"

	"charlie/i0.0.2/cls"
)

const (
	INSERT = iota
	UPDATE
	DELETE
	SELECT
)

type cert_sql struct {
	CertId  string
	CertVer int
}

type plugin_sql struct {
	PluginId      string
	PluginVer     int
	ProfileId     string
	ProfileVer    int
	PluginState   int
	PluginName    string
	PluginNicName string
}

// create the table in Sqlite
func CreateReqTableV(query string) int {
	if cls.SqliteDB == nil {
		lprintf(1, "[ERROR] SqliteDB error\n")
		return FAIL
	}

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] create statement error (%s)\n", err.Error())
		return FAIL
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		lprintf(1, "[ERROR] create table error (%s)\n", err.Error())
		return FAIL
	}

	return SUCCESS
}

// select the table in Sqlite cert
func SqlSelectCert(certId string) (int, []cert_sql) {

	var cert_ts []cert_sql
	var query string

	if len(certId) == 0 {
		query = fmt.Sprintf("SELECT CERT_ID, CERT_VER FROM CERT_TAB")
	} else {
		query = fmt.Sprintf("SELECT CERT_ID, CERT_VER FROM CERT_TAB WHERE CERT_ID = %s", certId)
	}
	lprintf(4, "[IFNO] select query : %s\n", query)

	rows, err := cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL, cert_ts
	}
	defer rows.Close()

	for rows.Next() {
		var cert_t cert_sql
		if err = rows.Scan(&cert_t.CertId, &cert_t.CertVer); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return FAIL, cert_ts
		}

		cert_ts = append(cert_ts, cert_t)
	}

	return SUCCESS, cert_ts
}

// sql statement cert
func SqlStatementCert(sqlFlag, ver int, id string) int {

	var query string

	if sqlFlag == UPDATE {
		query = "UPDATE CERT_TAB SET CERT_VER = ? WHERE CERT_ID = ?"
	} else if sqlFlag == INSERT {
		query = "INSERT INTO CERT_TAB (CERT_ID, CERT_VER) VALUES (?, ?)"
	} else if sqlFlag == DELETE {
		query = "DELETE FROM CERT_TAB WHERE CERT_ID = ?"
	}

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()

	if sqlFlag == UPDATE {
		_, err = statement.Exec(ver, id)
		if err != nil {
			lprintf(1, "[ERROR] sql update exec error : %s\n", err.Error())
			return FAIL
		}
	} else if sqlFlag == INSERT {
		_, err = statement.Exec(id, ver)
		if err != nil {
			lprintf(1, "[ERROR] sql insert exec error : %s\n", err.Error())
			return FAIL
		}
	} else if sqlFlag == DELETE {
		_, err = statement.Exec(id)
		if err != nil {
			lprintf(1, "[ERROR] sql delete exec error : %s\n", err.Error())
			return FAIL
		}
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// select the table in Sqlite edge
func SqlSelectEdge() int {

	query := fmt.Sprintf("SELECT UUID FROM EDGE_TAB WHERE EDGE_ID = 1")
	lprintf(4, "[IFNO] select query : %s\n", query)

	rows, err := cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL
	}
	defer rows.Close()

	for rows.Next() {
		if err = rows.Scan(&Agent_t.uuId); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return FAIL
		}

	}

	return SUCCESS
}

// sql statement edge
func SqlStatementEdge(sqlFlag int) int {

	var query string

	if sqlFlag == UPDATE {
		query = "UPDATE EDGE_TAB SET UUID = ? WHERE EDGE_ID = 1"
	} else if sqlFlag == INSERT {
		query = "INSERT INTO EDGE_TAB (EDGE_ID, UUID) VALUES (1, ?)"
	}

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()

	_, err = statement.Exec(Agent_t.uuId)
	if err != nil {
		lprintf(1, "[ERROR] sql update exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// select the table in Sqlite plugin
func SqlSelectPlugin() (int, []plugin_sql) {

	var plugin_ts []plugin_sql

	query := fmt.Sprintf("SELECT PLUGIN_ID, PLUGIN_VER, PROFILE_ID, PROFILE_VER, PLUGIN_STATE, PLUGIN_NAME, PLUGIN_NICNAME FROM PLUGIN_TAB")
	//query := fmt.Sprintf("SELECT PLUGIN_ID, PLUGIN_VER, PLUGIN_STATE, PLUGIN_NAME, PLUGIN_NICNAME FROM PLUGIN_TAB")
	lprintf(4, "[INFO] select query : %s\n", query)

	rows, err := cls.SqliteDB.Query(query)
	if err != nil {
		lprintf(1, "[ERROR] select error : %s\n", err.Error())
		return FAIL, plugin_ts
	}
	defer rows.Close()

	for rows.Next() {

		var plugin_t plugin_sql

		if err = rows.Scan(&plugin_t.PluginId, &plugin_t.PluginVer, &plugin_t.ProfileId, &plugin_t.ProfileVer, &plugin_t.PluginState, &plugin_t.PluginName, &plugin_t.PluginNicName); err != nil {
			lprintf(1, "[ERROR] sql scan error(%s)\n", err.Error())
			return FAIL, plugin_ts
		}

		plugin_ts = append(plugin_ts, plugin_t)
	}

	return SUCCESS, plugin_ts
}

// sql statement plugin
func SqlStatementPlugin(sqlFlag int, plugin_t plugin_sql) int {

	var query string

	if plugin_t.PluginName == "smartagent" {
		query = "INSERT OR REPLACE INTO PLUGIN_TAB (PLUGIN_ID, PLUGIN_VER, PROFILE_ID, PROFILE_VER, PLUGIN_STATE, PLUGIN_NICNAME, PLUGIN_NAME) VALUES (?, ?, ?, ?, ?, ?, ?)"
	} else if sqlFlag == UPDATE {
		query = "UPDATE PLUGIN_TAB SET PLUGIN_VER = ?, PROFILE_ID = ?, PROFILE_VER = ?, PLUGIN_STATE = ? WHERE PLUGIN_ID = ? AND PLUGIN_NICNAME = ?"
	} else if sqlFlag == INSERT {
		query = "INSERT INTO PLUGIN_TAB (PLUGIN_ID, PLUGIN_VER, PROFILE_ID, PROFILE_VER, PLUGIN_STATE, PLUGIN_NAME, PLUGIN_NICNAME) VALUES (?,?,?, ?, ?, ?, ?)"
	}

	lprintf(4, "[INFO] SqlStatementPlugin query : %s\n", query)
	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()

	if plugin_t.PluginName == "smartagent" {
		_, err = statement.Exec(plugin_t.PluginId, plugin_t.PluginVer, plugin_t.ProfileId, plugin_t.ProfileVer, 1, "DFA", "smartagent")
		if err != nil {
			lprintf(1, "[ERROR] sql update exec error : %s\n", err.Error())
			return FAIL
		}
	} else if sqlFlag == UPDATE {
		_, err = statement.Exec(plugin_t.PluginVer, plugin_t.ProfileId, plugin_t.ProfileVer, plugin_t.PluginState, plugin_t.PluginId, plugin_t.PluginNicName)
		if err != nil {
			lprintf(1, "[ERROR] sql update exec error : %s\n", err.Error())
			return FAIL
		}
	} else if sqlFlag == INSERT {
		_, err = statement.Exec(plugin_t.PluginId, plugin_t.PluginVer, plugin_t.ProfileId, plugin_t.ProfileVer, plugin_t.PluginState, plugin_t.PluginName, plugin_t.PluginNicName)
		if err != nil {
			lprintf(1, "[ERROR] sql insert exec error : %s\n", err.Error())
			return FAIL
		}
	}

	lprintf(4, "[INFO] statement query finished \n")
	return SUCCESS
}

// DELETE FROM CERT_TAB WHERE CERT_ID = %d
// sql delete plugin
func SqlDeletePlugin(plugin_t plugin_sql) int {

	query := "DELETE FROM PLUGIN_TAB WHERE PLUGIN_ID = ? and PLUGIN_NICNAME = ?"
	lprintf(4, "[IFNO] delete query : %s\n", query)

	statement, err := cls.SqliteDB.Prepare(query)
	if err != nil {
		lprintf(1, "[ERROR] sql prepare error : %s\n", err.Error())
		return FAIL
	}
	defer statement.Close()

	_, err = statement.Exec(plugin_t.PluginId, plugin_t.PluginNicName)
	if err != nil {
		lprintf(1, "[ERROR] sql update exec error : %s\n", err.Error())
		return FAIL
	}

	lprintf(4, "[INFO] delete query finished \n")
	return SUCCESS
}

func SqlOperation(sqlFlag int, val Operation_s) int {

	var plugin_sql_t plugin_sql

	plugin_sql_t.PluginId = val.PlgId
	plugin_sql_t.PluginVer = val.PlgVer
	plugin_sql_t.ProfileId = val.ProID
	plugin_sql_t.ProfileVer = val.ProVer

	plugin_sql_t.PluginNicName = val.NicName
	plugin_sql_t.PluginName = val.PlgName
	plugin_sql_t.PluginState = YES

	if SqlStatementPlugin(sqlFlag, plugin_sql_t) < 0 {
		lprintf(1, "[ERROR] SqlStatementPlugin fail \n")
		return FAIL
	}

	return SUCCESS
}
