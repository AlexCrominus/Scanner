// db.go
package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB(dataSourceName string) {
	var err error
	DB, err = sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Fatal(err)
	}

	createTableSQL := `CREATE TABLE IF NOT EXISTS targets (
		"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"type" TEXT,
		"value" TEXT
	);`
	_, err = DB.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}
}

func StoreDomain(domain string) {
	stmt, err := DB.Prepare("INSERT INTO targets(type, value) VALUES(?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	_, err = stmt.Exec("domain", domain)
	if err != nil {
		log.Fatal(err)
	}
}

func StoreDomains(domains []string) {
	for _, domain := range domains {
		StoreDomain(domain)
	}
}

func StoreIP(ip string) {
	stmt, err := DB.Prepare("INSERT INTO targets(type, value) VALUES(?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	_, err = stmt.Exec("IP address", ip)
	if err != nil {
		log.Fatal(err)
	}
}

func StoreIPs(ips []string) {
	for _, ip := range ips {
		StoreIP(ip)
	}
}

func GetAllTargets() ([]map[string]string, error) {
	rows, err := DB.Query("SELECT type, value FROM targets")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []map[string]string
	for rows.Next() {
		var targetMap = make(map[string]string)
		var target, value string
		if err := rows.Scan(&target, &value); err != nil {
			return nil, err
		}
		targetMap["type"] = target
		targetMap["value"] = value
		targets = append(targets, targetMap)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}
