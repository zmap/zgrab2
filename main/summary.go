package main

import "github.com/zmap/zgrab2"

type Summary struct {
	StatusesPerModule map[string]*zgrab2.State `json:"statuses"`
	StartTime         string                   `json:"start"`
	EndTime           string                   `json:"end"`
	Duration          string                   `json:"duration"`
}
