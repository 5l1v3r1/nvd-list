package main

import (
	"time"
)


type LastUpdated struct {
	Date time.Time
}

type NVD struct {
	CVEItems []interface{} `json:"CVE_Items"`
}

