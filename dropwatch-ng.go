package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"dropwatch-ng/dissector"
	"dropwatch-ng/dropmon"
	"dropwatch-ng/exporter"
)

const (
	DW_DEFAULT_CONF_FILE = "/etc/dropwatch/dropwatch.yml"
	DW_CONF_ENV_PREFIX   = "DROPWATCH"
)

type DWConfig struct {
	logger    *log.Logger
	exporters []exporter.Exporter
}

func processAlertMessages(alertCh chan *dropmon.AlertMsg, exporters []exporter.Exporter, done chan struct{}) {
	var packetNo uint64

	ds := dissector.NewBasicDissector()

	for {
		select {
		case <-done:
			return
		case alertMsg := <-alertCh:
			packetNo++
			packet, err := ds.DissectPacket(alertMsg.Packet.Payload)
			if packet == nil {
				fmt.Printf("error dissecting packet: %v", err)
				continue
			}

			msg := exporter.WriteMsg{AlertMsg: alertMsg, Packet: packet}

			for _, ex := range exporters {
				ex.Write(&msg)
			}
		default:
			continue
		}
	}
}

func readConfigFile(filename string) error {
	viper.SetConfigFile(filename)

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("error reading config file %s: %v", filename, err)
	}
	return nil
}

func readConfigEnv(envPrefix string) {
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()
}

func parseFlags() {
	pflag.Int("flagname", 1234, "help message for flagname")
}

func startExporters() []exporter.Exporter {
	var exporters []exporter.Exporter
	// PCAP exporter
	subPCAP := viper.Sub("exporters.pcap")
	if subPCAP != nil {
		pcapCfg := exporter.PCAPExporterConfig{}
		err := subPCAP.Unmarshal(&pcapCfg)
		if err == nil {
			pcap := exporter.NewPCAPExporter(&pcapCfg)
			pcap.Start()
			exporters = append(exporters, pcap)
		} else {
			fmt.Printf("error parsing pcap exporter config: %v\n", err)
		}
	}

	// Telegraf exporter
	subTelegraf := viper.Sub("exporters.telegraf")
	if subTelegraf != nil {
		telegrafCfg := exporter.TelegrafExporterConfig{}
		err := subTelegraf.Unmarshal(&telegrafCfg)
		if err == nil {
			telegraf := exporter.NewTelegrafExporter(&telegrafCfg)
			telegraf.Start()
			exporters = append(exporters, telegraf)
		} else {
			fmt.Printf("error parsing telegraf exporter config: %v\n", err)
		}
	}
	return exporters
}

func main() {
	var err error
	var exporters []exporter.Exporter

	configFile := flag.String("c", DW_DEFAULT_CONF_FILE, "Path to config file (YAML)")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	// try reading configuration from file
	err = readConfigFile(*configFile)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("= using config file: %s\n", *configFile)
	}
	readConfigEnv(DW_CONF_ENV_PREFIX)

	dm := dropmon.NewDropMon()
	err = dm.Init()
	if err != nil {
		log.Fatal(err)
	}
	dm.SetAlertMode(dropmon.NET_DM_ALERT_MODE_PACKET)
	if err != nil {
		fmt.Printf("error setting packet alert mode: %v\n", err)
	}

	// dm.SetTruncLen(1000)
	// dm.DisableDropMonitor(true, true)

	err = dm.EnableDropMonitor(false, true)
	if err != nil {
		fmt.Printf("error enabling drop monitor: %v\n", err)
	}

	// start drop monitor
	alertCh := make(chan *dropmon.AlertMsg)
	dm.Start(alertCh)

	// print drop events to stdout
	if *verbose {
		stdoutCfg := exporter.StdoutExporterConfig{Tabular: false}
		stdout := exporter.NewStdoutExporter(&stdoutCfg)
		stdout.Start()
		exporters = append(exporters, stdout)
	}

	newExporters := startExporters()
	exporters = append(exporters, newExporters...)

	// start processing dropmon events with exporters
	done := make(chan struct{}, 1)
	go processAlertMessages(alertCh, exporters, done)

	sigs := make(chan os.Signal, 1)
	exited := make(chan struct{}, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Exiting...")
		done <- struct{}{}
		err = dm.DisableDropMonitor(true, true)
		if err != nil {
			log.Fatalf("error disabling drop monitor: %v\n", err)
		}

		exited <- struct{}{}
	}()
	<-exited
	close(sigs)
	close(exited)
	close(done)
}
