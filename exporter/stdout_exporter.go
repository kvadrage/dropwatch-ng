package exporter

import (
	"encoding/json"
	"fmt"
)

type StdoutExporterConfig struct {
	Tabular bool
}

type StdoutExporter struct {
	config     *StdoutExporterConfig
	stopped    chan struct{}
	inMessages chan *WriteMsg
}

func NewStdoutExporter(cfg *StdoutExporterConfig) *StdoutExporter {
	ex := StdoutExporter{}
	ex.config = cfg
	ex.stopped = make(chan struct{})
	return &ex
}

func (ex *StdoutExporter) Start() error {
	if ex.inMessages != nil {
		return fmt.Errorf("StdoutExporter already started")
	}

	ex.inMessages = make(chan *WriteMsg)

	go func() {
		fmt.Println("= StdoutExporter started")
		defer func() {
			close(ex.inMessages)
			fmt.Println("= StdoutExporter stopped")
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
func (ex *StdoutExporter) Stop() {
	ex.stopped <- struct{}{}
}

// Write message to exporter
func (ex *StdoutExporter) Write(msg *WriteMsg) error {
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

func (ex *StdoutExporter) processMsg(msg *WriteMsg) error {
	var err error

	alertMsg := msg.AlertMsg
	packet := msg.Packet

	if alertMsg == nil {
		return fmt.Errorf("AlertMsg is NIL")
	}
	fmt.Printf("drop at: %s (%s)\n", alertMsg.Trap, alertMsg.Group)
	fmt.Printf("origin: %s\n", alertMsg.Origin)
	fmt.Printf("input port ifindex: %d\n", alertMsg.Port.InPortIfIndex)
	fmt.Printf("input port name: %s\n", alertMsg.Port.InPortName)
	fmt.Printf("timestamp: %v\n", alertMsg.Timestamp)
	fmt.Printf("protocol: %#x\n", alertMsg.Packet.Protocol)
	fmt.Printf("length: %d\n", alertMsg.Packet.Length)
	fmt.Printf("original length: %d\n", alertMsg.Packet.OrigLength)
	if packet != nil {
		jsonData, err := json.Marshal(packet)
		if err != nil {
			err = fmt.Errorf("JSON Marshalling error: %v\n", err)
		} else {
			fmt.Printf("Packet: %s\n", string(jsonData))
		}
	}

	fmt.Println("")

	return err
}
