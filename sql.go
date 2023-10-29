package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// Main table: releases(ocp_release, bugs)
// Sub tables: 4.10.1-cves(release, cve, cvelink)
// 			4.10.1-fixes(bzID, description)

func insertCVEDetail(db *sql.DB, tableName string, release string, cve string, cveLink string) {
	query := "INSERT INTO " + tableName + "(release, cve, cvelink) values(?, ?, ?)"
	stmt, err := db.Prepare(query)
	checkErr(err)
	_, err = stmt.Exec(release, cve, cveLink)
	checkErr(err)
}

func insertFixesDetail(db *sql.DB, tableName string, release string, fixes map[string]string) {
	query := "INSERT INTO " + tableName + "(release, bzID, description) values(?, ?, ?)"
	stmt, err := db.Prepare(query)
	checkErr(err)
	for id, desc := range fixes {
		// log.Printf("Inserting %s with %s", id, desc)
		_, err = stmt.Exec(release, id, desc)
		checkErr(err)
	}
}

func createTable(db *sql.DB, tableName string, isCVE bool) {
	var query string
	log.Printf("creating table %s", tableName)
	if isCVE {
		query = "CREATE TABLE IF NOT EXISTS " + tableName + "(release varchar, cve varchar, cvelink varchar)"
	} else {
		query = "CREATE TABLE IF NOT EXISTS " + tableName + "(release varchar,bzID varchar, description varchar)"
	}
	db.Exec(query)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func verifyTable(db *sql.DB, release string) bool {
	log.Printf("Verifying content, if release %s already exist", release)
	fixcheck := db.QueryRow("SELECT * FROM fixes WHERE release=?", release)
	cvecheck := db.QueryRow("SELECT * FROM cves WHERE release=?", release)
	return fixcheck.Scan() == sql.ErrNoRows && cvecheck.Scan() == sql.ErrNoRows
}
