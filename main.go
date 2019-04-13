package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	jsonpointer "github.com/mattn/go-jsonpointer"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

const (
	baseURL         = "https://nvd.nist.gov/feeds/json/cve/1.0"
	cvesDir         = "cves"
	lastUpdatedFile = "last_updated.txt"
)

func main() {
	if err := update(); err != nil {
		log.Fatal(err)
	}
	if err := push(); err != nil {
		log.Fatal(err)
	}
}

func update() error {
	now := time.Now().UTC()

	var old bool
	var feeds []string
	for _, feed := range []string{"modified", "recent"} {
		lastModifiedDate, err := fetchLastModifiedDate(feed)
		if err != nil {
			return err
		}
		lastUpdatedDate, err := getLastUpdatedDate()
		if err != nil {
			return err
		}

		if lastUpdatedDate.After(lastModifiedDate) {
			continue
		}
		feeds = append(feeds, feed)

		duration := lastModifiedDate.Sub(lastUpdatedDate)
		if duration > 24*time.Hour*7 {
			old = true
		}
	}

	if old {
		// Fetch all years
		feeds = []string{}
		for year := 2002; year <= now.Year(); year++ {
			feeds = append(feeds, fmt.Sprint(year))
		}
	}

	feedCount := len(feeds)
	if feedCount == 0 {
		return nil
	}

	log.Println("Fetching NVD data...")
	bar := pb.StartNew(feedCount)

	results := make(chan *NVD)
	errCh := make(chan error)
	limit := make(chan struct{}, 5)
	for _, feed := range feeds {
		go func(feed string) {
			limit <- struct{}{}
			nvd, err := fetchJson(feed)
			if err != nil {
				errCh <- err
				return
			}
			results <- nvd
			<-limit
		}(feed)
	}

	for i := 0; i < feedCount; i++ {
		select {
		case nvd := <-results:
			if err := save(nvd); err != nil {
				return err
			}
		case err := <-errCh:
			return err
		}
		bar.Increment()
	}
	bar.Finish()

	err := setLastUpdatedDate(now)
	if err != nil {
		return err
	}

	return nil

}

func getLastUpdatedDate() (time.Time, error) {
	if _, err := os.Stat(lastUpdatedFile); os.IsNotExist(err) {
		return time.Unix(0, 0), nil
	}

	f, err := os.Open(lastUpdatedFile)
	if err != nil {
		return time.Time{}, err
	}

	decoder := json.NewDecoder(f)
	lastUpdated := LastUpdated{}
	if err = decoder.Decode(&lastUpdated); err != nil {
		return time.Time{}, err
	}

	return lastUpdated.Date, nil
}

func setLastUpdatedDate(lastUpdatedDate time.Time) error {
	d := LastUpdated{Date: lastUpdatedDate}
	f, err := os.OpenFile(lastUpdatedFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	return nil
}

func save(nvd *NVD) error {
	for _, item := range nvd.CVEItems {
		v, err := jsonpointer.Get(item, "/cve/CVE_data_meta/ID")
		if err != nil {
			log.Println(err)
			continue
		}

		cveID, ok := v.(string)
		if !ok {
			log.Println("failed to type assertion")
			continue
		}

		s := strings.Split(cveID, "-")
		if len(s) != 3 {
			continue
		}
		yearDir := filepath.Join(cvesDir, s[1])
		os.MkdirAll(yearDir, os.ModePerm)

		fileName := filepath.Join(yearDir, fmt.Sprintf("%s.json", cveID))
		err = write(fileName, item)
		if err != nil {
			return err
		}
	}
	return nil
}

func write(fileName string, data interface{}) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func fetchLastModifiedDate(feed string) (time.Time, error) {
	log.Printf("Fetching NVD metadata(%s)...\n", feed)

	url := fmt.Sprintf("%s/nvdcve-1.0-%s.meta", baseURL, feed)
	res, err := http.Get(url)
	if err != nil {
		return time.Time{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return time.Time{}, xerrors.New("error")
	}

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := scanner.Text()
		s := strings.SplitN(line, ":", 2)
		if len(s) != 2 {
			continue
		}
		if s[0] == "lastModifiedDate" {
			t, err := time.Parse(time.RFC3339, s[1])
			if err != nil {
				return time.Time{}, err
			}
			return t, nil
		}
	}
	return time.Unix(0, 0), nil

}

func fetchJson(feed string) (*NVD, error) {
	url := fmt.Sprintf("%s/nvdcve-1.0-%s.json.gz", baseURL, feed)

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, xerrors.New("error")
	}

	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	nvd := &NVD{}
	err = json.NewDecoder(zr).Decode(nvd)
	if err != nil {
		return nil, err
	}
	return nvd, nil
}
