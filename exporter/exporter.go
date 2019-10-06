package exporter

import (
	"dropwatch-ng/dropmon"
	"dropwatch-ng/dissector"
)

// Exporter generic interface
type Exporter interface {
	Start() error
	Stop()
	Write(msg *WriteMsg) error 	
}

// WriteMsg to process by exporter
type WriteMsg struct {
	AlertMsg *dropmon.AlertMsg
	Packet *dissector.Packet
}