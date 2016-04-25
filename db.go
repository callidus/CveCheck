package main

import (
	"compress/gzip"
	"database/sql"
	"encoding/xml"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// objects parsed out of the NVD XML stream
// ---------------------------------------------------------------------------

// Nvd is an array of Entry
type Nvd struct {
	Entries []Entry `xml:"entry"`
}

// Entry is Root Element
type Entry struct {
	CveID            string      `xml:"id,attr" json:"id"`
	PublishedDate    time.Time   `xml:"published-datetime"`
	LastModifiedDate time.Time   `xml:"last-modified-datetime"`
	Cvss             Cvss        `xml:"cvss>base_metrics" json:"cvss"`
	Products         []string    `xml:"vulnerable-software-list>product"` //CPE
	Summary          string      `xml:"summary"`
	References       []Reference `xml:"references"`
}

// Cvss is Cvss Score
type Cvss struct {
	Score                 string    `xml:"score"`
	AccessVector          string    `xml:"access-vector"`
	AccessComplexity      string    `xml:"access-complexity"`
	Authentication        string    `xml:"authentication"`
	ConfidentialityImpact string    `xml:"confidentiality-impact"`
	IntegrityImpact       string    `xml:"integrity-impact"`
	AvailabilityImpact    string    `xml:"availability-impact"`
	Source                string    `xml:"source"`
	GeneratedOnDate       time.Time `xml:"generated-on-datetime"`
}

// Reference is additional information about the CVE
type Reference struct {
	Type   string `xml:"reference_type,attr"`
	Source string `xml:"source"`
	Link   Link   `xml:"reference"`
}

// Link is additional information about the CVE
type Link struct {
	Value string `xml:",chardata" json:"value"`
	Href  string `xml:"href,attr" json:"href"`
}

// ---------------------------------------------------------------------------

func build_tabs(db *sql.DB) {
	tx, err := db.Begin()
	checkErr(err)
	sqlStmt := `
    create table IF NOT EXISTS Entries
      (CveID TEXT PRIMARY KEY,
       PublishedDate DATETIME,
       LastModifiedDate DATETIME,
       Summary TEXT)`

	_, err = tx.Exec(sqlStmt)
	checkErr(err)

	sqlStmt = `
    create table IF NOT EXISTS Products
      (Id INTEGER PRIMARY KEY AUTOINCREMENT,
       CveID TEXT,
       Value TEXT,
       FOREIGN KEY(CveID) REFERENCES Entries(CveID))`

	_, err = tx.Exec(sqlStmt)
	checkErr(err)

	sqlStmt = `
    create table IF NOT EXISTS CveRefs
      (Id INTEGER PRIMARY KEY AUTOINCREMENT,
       CveID TEXT,
       Type TEXT,
       Source TEXT,
       LinkValue TEXT,
       LinkHref TEXT,
       FOREIGN KEY(CveID) REFERENCES Entries(CveID))`

	_, err = tx.Exec(sqlStmt)
	checkErr(err)

	sqlStmt = `
    create table IF NOT EXISTS Cvss
      (Id INTEGER PRIMARY KEY AUTOINCREMENT,
       CveID TEXT,
       Score TEXT,
       AccessVector TEXT,
       AccessComplexity TEXT,
       Authentication TEXT,
       ConfidentialityImpact TEXT,
       IntegrityImpact TEXT,
       AvailabilityImpact TEXT,
       Source TEXT,
       GeneratedOnDate DATETIME,
       FOREIGN KEY(CveID) REFERENCES Entries(CveID))`

	_, err = tx.Exec(sqlStmt)
	checkErr(err)
	tx.Commit()
}

func insert_entry(db *sql.DB, entry *Entry) {
	tx, err := db.Begin()
	checkErr(err)

	sqlStmt, err := tx.Prepare(`
    INSERT INTO Entries (CveID, PublishedDate, LastModifiedDate, Summary)
    VALUES (?, ?, ?, ?)`)
	checkErr(err)

	_, err = sqlStmt.Exec(entry.CveID, entry.PublishedDate,
		entry.LastModifiedDate, entry.Summary)
	checkErr(err)

	sqlStmt, err = tx.Prepare(`
    INSERT INTO Products (CveID, Value)
    VALUES (?, ?)`)
	checkErr(err)
	for _, val := range entry.Products {
		_, err = sqlStmt.Exec(entry.CveID, val)
		checkErr(err)
	}

	sqlStmt, err = tx.Prepare(`
    INSERT INTO CveRefs (CveID, Type, Source, LinkValue, LinkHref)
    VALUES (?, ?, ?, ?, ?)`)
	checkErr(err)
	for _, val := range entry.References {
		_, err = sqlStmt.Exec(entry.CveID, val.Type, val.Source,
			val.Link.Value, val.Link.Href)
		checkErr(err)
	}

	sqlStmt, err = tx.Prepare(`
    INSERT INTO Cvss (CveID, Score, AccessVector, AccessComplexity,
                      Authentication, ConfidentialityImpact, IntegrityImpact,
                      AvailabilityImpact, Source, GeneratedOnDate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	checkErr(err)
	_, err = sqlStmt.Exec(entry.CveID,
		entry.Cvss.Score,
		entry.Cvss.AccessVector,
		entry.Cvss.AccessComplexity,
		entry.Cvss.Authentication,
		entry.Cvss.ConfidentialityImpact,
		entry.Cvss.IntegrityImpact,
		entry.Cvss.AvailabilityImpact,
		entry.Cvss.Source,
		entry.Cvss.GeneratedOnDate)
	checkErr(err)
	tx.Commit()
}

func fill_nvd(db *sql.DB) {
	tpl := "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz"
	for i := 2; i < 16; i++ { // 2002 - 2016
		url := fmt.Sprintf(tpl, 2000+i)
		fmt.Println(url)
		resp, err := http.Get(url)
		checkErr(err)

		defer resp.Body.Close()
		body, err := gzip.NewReader(resp.Body)
		checkErr(err)
		data, err := ioutil.ReadAll(body)
		checkErr(err)

		var q Nvd
		err = xml.Unmarshal(data, &q)
		fmt.Println(len(q.Entries))
		checkErr(err)

		for _, val := range q.Entries {
			insert_entry(db, &val)
		}
	}
}

func update_nvd(db *sql.DB) {
	//TODO: just update new data
}

func main() {
	// path should probably come form stdin ...
	path := "./nvd.db"
	full := false

	// do a full update if the DB file is missing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		full = true
	}

	db, err := sql.Open("sqlite3", path)
	checkErr(err)

	if full {
		build_tabs(db)
		fill_nvd(db)
	} else {
		update_nvd(db)
	}
	db.Close()
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
