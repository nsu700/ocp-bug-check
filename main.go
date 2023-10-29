package main

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gocolly/colly/v2"
)

var (
	re        = regexp.MustCompile(`OpenShift Container Platform release 4.1?[0-9].[0-9]+`)
	ERRATARE  = regexp.MustCompile(`RH[BES]A-\d{4}:\d{4}`)
	RELEASERE = regexp.MustCompile(`4.1?[0-9].[0-9]+`)
	// TODO: fix below both, better to parse the link from a single match
	bugFiXRE        = regexp.MustCompile(`bug fixes .*? RH[BES]A-\d{4}:\d{4}`)
	rpmRE           = regexp.MustCompile(`RPM packages .* RH[BS]A-\d{4}:\d{4}`)
	URL             = "https://docs.openshift.com/container-platform/4.RELEASE/release_notes/ocp-4-RELEASE-release-notes.html#ocp-4-RELEASE-asynchronous-errata-updates"
	UPDATE          = false
	ERRATA_PREFIX   = "https://access.redhat.com/errata/"
	CVE_PREFIX      = "https://access.redhat.com/security/cve/"
	DB_FILE         = "ocp-bugs.db"
	DB_DRIVER       = "sqlite3"
	CVE_TABLE_NAME  = "cves"
	FIX_TABLE_NAME  = "fixes"
	MAIN_TABLE_NAME = "main"
)

func main() {
	version := 8

	db, err := sql.Open(DB_DRIVER, DB_FILE)
	checkErr(err)
	defer db.Close()

	createTable(db, CVE_TABLE_NAME, true)
	createTable(db, FIX_TABLE_NAME, false)

	for {
		version++
		v := strconv.Itoa(version)
		if verifyPage(v) {
			parseBug(db, getRelease(v))
		} else {
			break
		}
	}
}

func StandardizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func getRelease(version string) map[string][]string {
	c := colly.NewCollector()
	var ocp_release = make(map[string][]string)
	c.OnHTML("div.paragraph", func(e *colly.HTMLElement) {
		text := e.Text
		if re.MatchString(text) {
			release := RELEASERE.FindAllString(text, -1)
			bugFixContent := bugFiXRE.FindAllString(text, -1)
			var bugs []string
			for _, sentence := range bugFixContent {
				bugs = append(bugs, ERRATARE.FindString(sentence))
			}
			ocp_release[release[0]] = bugs
		}
	})

	c.OnRequest(func(r *colly.Request) {
		log.Println("Visiting", r.URL.String())
	})

	c.Visit(strings.ReplaceAll(URL, "RELEASE", version))
	return ocp_release
}

func verifyPage(v string) bool {
	resp, _ := http.Head("https://docs.openshift.com/container-platform/4." + v)
	if resp.StatusCode >= 400 {
		return false
	} else {
		return true
	}
}

func parseBug(db *sql.DB, releases map[string][]string) {

	c := colly.NewCollector()

	var fixes = make(map[string]string)
	var release string

	c.OnHTML("div[id=fixes]", func(e *colly.HTMLElement) {
		e.ForEach("li", func(i int, el *colly.HTMLElement) {
			bzID := strings.Split(el.Text, "- ")
			if len(bzID) == 2 {
				fixes[bzID[0]] = strings.TrimSpace(bzID[1])
			} else {
				fixes[bzID[1]] = strings.TrimSpace(strings.Join(bzID[2:], " "))
			}
		})
		insertFixesDetail(db, FIX_TABLE_NAME, release, fixes)
	})

	c.OnHTML("div[id=cves]", func(e *colly.HTMLElement) {
		e.ForEach("li", func(i int, el *colly.HTMLElement) {
			cveID := el.Text
			cveLink := CVE_PREFIX + cveID
			insertCVEDetail(db, CVE_TABLE_NAME, release, cveID, cveLink)
		})
	})

	for r, bugs := range releases {
		release = r
		if !verifyTable(db, r) {
			continue
		}
		// Verify if table exist or not, if yes, skip the release
		log.Println("Checking OCP release:" + release)
		for _, bug := range bugs {
			log.Println(ERRATA_PREFIX + bug)
			c.Visit(ERRATA_PREFIX + bug)
		}
	}

	c.Wait()
}
