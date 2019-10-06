package exporter

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PCAPExporterConfig struct {
	FileName string `mapstructure:"file_name"`
}

type PCAPExporter struct {
	config          *PCAPExporterConfig
	stopped         chan struct{}
	inMessages      chan *WriteMsg
	writePcap       bool
	pcapFile        *os.File
	pcapWriter      *pcapgo.Writer
	pcapPacketCount uint32
}

const (
	PCAP_HDR_SNAPSHOT_LEN = 65536
)

func NewPCAPExporter(cfg *PCAPExporterConfig) *PCAPExporter {
	ex := PCAPExporter{}
	ex.config = cfg
	ex.stopped = make(chan struct{})
	return &ex
}

func (ex *PCAPExporter) Start() error {
	var err error
	if ex.inMessages != nil {
		return fmt.Errorf("error: PCAPExporter already started")
	}

	ex.pcapFile, err = os.Create(ex.config.FileName)
	if err != nil {
		return fmt.Errorf("error creating PCAP file %s: %v", ex.config.FileName, err)
	}

	ex.pcapWriter = pcapgo.NewWriter(ex.pcapFile)
	err = ex.pcapWriter.WriteFileHeader(PCAP_HDR_SNAPSHOT_LEN, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("error starting PCAP write session: %v", err)
	}

	ex.pcapPacketCount = 0
	ex.inMessages = make(chan *WriteMsg)

	go func() {
		fmt.Println("= PCAPExporter started")
		fmt.Println("== File name:", ex.config.FileName)
		defer func() {
			close(ex.inMessages)
			if ex.pcapFile != nil {
				ex.pcapFile.Close()
			}
			fmt.Println("= PCAPExporter stopped")
		}()
		for {
			select {
			case <-ex.stopped:
				// process stop signal
				return
			case msg := <-ex.inMessages:
				// process message
				ex.processMsg(msg)
			default:
				continue
			}
		}
	}()
	return nil
}

// Stop exporter
func (ex *PCAPExporter) Stop() {
	ex.stopped <- struct{}{}
}

// Write message to exporter
func (ex *PCAPExporter) Write(msg *WriteMsg) error {
	if msg == nil {
		return fmt.Errorf("error: WriteMsg is NIL ")
	}

	// send message
	go func() {
		if ex.inMessages != nil {
			ex.inMessages <- msg
		}
	}()
	return nil
}

func (ex *PCAPExporter) processMsg(msg *WriteMsg) error {
	var err error
	alertMsg := msg.AlertMsg
	if alertMsg == nil {
		return fmt.Errorf("AlertMsg is NIL")
	}

	captureInfo := gopacket.CaptureInfo{
		Timestamp:      msg.AlertMsg.Timestamp,
		CaptureLength:  int(msg.AlertMsg.Packet.Length),
		Length:         int(msg.AlertMsg.Packet.OrigLength),
		InterfaceIndex: int(msg.AlertMsg.Port.InPortIfIndex),
	}
	err = ex.pcapWriter.WritePacket(captureInfo, msg.AlertMsg.Packet.Payload)
	if err != nil {
		fmt.Printf("error writing to PCAP file %s: %v", ex.config.FileName, err)
	}
	ex.pcapPacketCount++

	return err
}
