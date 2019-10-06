package exporter

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"dropwatch-ng/dissector"

	"github.com/golang-collections/go-datastructures/queue"
)

type TelegrafMsg struct {
	DropType    string            `json:"dropType"`
	DropReason  string            `json:"dropReason"`
	IngressPort string            `json:"ingressPort"`
	Severity    string            `json:"severity"`
	DeviceIP    string            `json:"deviceIP"`
	Timestamp   string            `json:"timestamp"`
	Message     string            `json:"message"`
	Packet      *dissector.Packet `json:"packet"`
}

type TelegrafExporterConfig struct {
	DeviceIP     string        `mapstructure:"device_ip"`
	ConnAddr     string        `mapstructure:"conn_addr"`
	ConnTimeout  time.Duration `mapstructure:"conn_timeout"`
	SendInterval time.Duration `mapstructure:"send_interval"`
}

type TelegrafExporter struct {
	config     *TelegrafExporterConfig
	stopped    chan struct{}
	inMessages chan *WriteMsg
	sendQueue  *queue.Queue
	conn       net.Conn
}

func NewTelegrafExporter(cfg *TelegrafExporterConfig) *TelegrafExporter {
	ex := TelegrafExporter{}
	ex.config = cfg
	ex.stopped = make(chan struct{})
	return &ex
}

func (ex *TelegrafExporter) Start() error {
	if ex.inMessages != nil {
		return fmt.Errorf("TelegrafExporter already started")
	}

	ex.inMessages = make(chan *WriteMsg)
	ex.sendQueue = queue.New(100)
	sendTicker := time.NewTicker(ex.config.SendInterval)

	go func() {
		fmt.Println("= TelegrafExporter started")
		fmt.Println("== Connection address:", ex.config.ConnAddr)
		fmt.Println("== Device IP:", ex.config.DeviceIP)
		fmt.Println("== Send interval:", ex.config.SendInterval)
		defer func() {
			close(ex.inMessages)
			fmt.Println("= TelegrafExporter stopped")
		}()

		for {
			select {
			case <-ex.stopped:
				// process stop signal
				return
			case msg := <-ex.inMessages:
				// process message
				tgMsg, err := ex.processMsg(msg)
				if err != nil {
					fmt.Printf("Error processing message: %v", err)
					continue
				}
				ex.sendQueue.Put(tgMsg)
			case <-sendTicker.C:
				all := func(item interface{}) bool {
					return true
				}
				items, err := ex.sendQueue.TakeUntil(all)
				if err != nil || len(items) == 0 {
					continue
				}
				sendMessages := make([]*TelegrafMsg, 0, len(items))
				for _, item := range items {
					msg := item.(*TelegrafMsg)
					sendMessages = append(sendMessages, msg)
				}
				go ex.sendJSON(sendMessages)
			default:
				continue
			}
		}
	}()
	return nil
}

func (ex *TelegrafExporter) Stop() {
	ex.stopped <- struct{}{}
}

func (ex *TelegrafExporter) Write(msg *WriteMsg) error {
	if msg == nil {
		return fmt.Errorf("Error: WriteMsg is NIL ")
	}

	// send message
	go func() {
		if ex.inMessages != nil {
			ex.inMessages <- msg
		}
	}()
	return nil
}

func (ex *TelegrafExporter) processMsg(msg *WriteMsg) (*TelegrafMsg, error) {
	var tgMsg *TelegrafMsg

	alertMsg := msg.AlertMsg
	packet := msg.Packet

	if alertMsg == nil {
		return nil, fmt.Errorf("AlertMsg is NIL")
	}

	tgMsg = new(TelegrafMsg)
	switch alertMsg.Group {
	case "l2_drops":
		tgMsg.DropType = "l2"
	case "l3_drops":
		tgMsg.DropType = "l3"
	default:
		tgMsg.DropType = "unknown"
	}
	tgMsg.DropReason = alertMsg.Trap
	tgMsg.IngressPort = alertMsg.Port.InPortName
	tgMsg.Severity = "Notice"
	tgMsg.DeviceIP = ex.config.DeviceIP
	sec := alertMsg.Timestamp.Unix()
	ns := alertMsg.Timestamp.Nanosecond()
	tgMsg.Timestamp = fmt.Sprintf("%d.%d", sec, ns)
	tgMsg.Message = "fwdDrop"
	tgMsg.Packet = packet

	return tgMsg, nil
}

func (ex *TelegrafExporter) sendJSON(messages []*TelegrafMsg) error {
	jsonMsg, err := json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("JSON Marshalling error: %v\n", err)
	}

	conn, err := net.Dial("tcp", ex.config.ConnAddr)
	if err != nil {
		return err
	}
	_, err = conn.Write(jsonMsg)
	conn.Close()
	return err
}
