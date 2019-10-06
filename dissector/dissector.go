package dissector

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type BasicDissector struct {
}

func NewBasicDissector() *BasicDissector {
	ds := BasicDissector{}
	return &ds
}

func (ds *BasicDissector) DissectPacket(data []byte) (*Packet, error) {
	var err error

	var packet *Packet

	var eth layers.Ethernet
	var vlan layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	dlc = dlc.Put(&eth)
	dlc = dlc.Put(&vlan)
	dlc = dlc.Put(&ip4)
	dlc = dlc.Put(&ip6)
	dlc = dlc.Put(&tcp)
	dlc = dlc.Put(&udp)
	dlc = dlc.Put(&payload)
	// you may specify some meaningful DecodeFeedback
	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)
	lt, err := decoder(data, &decoded)
	if err != nil {
		err = fmt.Errorf("Could not decode layers: %v\n", err)
	}
	if lt != gopacket.LayerTypeZero {
		err = fmt.Errorf("unknown layer type: %v\n", lt)
	}
	packet = new(Packet)
	for _, typ := range decoded {
		switch typ {
		case layers.LayerTypeEthernet:
			if packet.Ethernet == nil {
				packet.Ethernet = new(PacketEthernet)
			}
			srcMAC := eth.SrcMAC.String()
			dstMAC := eth.DstMAC.String()
			etherType := uint16(eth.EthernetType)
			packet.Ethernet.SrcMAC = &srcMAC
			packet.Ethernet.DstMAC = &dstMAC
			packet.Ethernet.EtherType = &etherType
		case layers.LayerTypeDot1Q:
			if packet.Ethernet == nil {
				packet.Ethernet = new(PacketEthernet)
			}
			vid := uint16(vlan.VLANIdentifier)
			pcp := uint8(vlan.Priority)
			packet.Ethernet.VlanID = &vid
			packet.Ethernet.PCP = &pcp
		case layers.LayerTypeIPv4:
			if packet.IP == nil {
				packet.IP = new(PacketIP)
			}
			srcIP := ip4.SrcIP.String()
			dstIP := ip4.DstIP.String()
			proto := uint16(ip4.Protocol)
			tos := uint8(ip4.TOS)
			ttl := uint8(ip4.TTL)
			packet.IP.SrcIP = &srcIP
			packet.IP.DstIP = &dstIP
			packet.IP.Protocol = &proto
			packet.IP.TOS = &tos
			packet.IP.TTL = &ttl
		case layers.LayerTypeIPv6:
			if packet.IP == nil {
				packet.IP = new(PacketIP)
			}
			srcIP := ip6.SrcIP.String()
			dstIP := ip6.DstIP.String()
			proto := uint16(ip6.NextHeader)
			tos := uint8(ip6.TrafficClass)
			ttl := uint8(ip6.HopLimit)
			packet.IP.SrcIP = &srcIP
			packet.IP.DstIP = &dstIP
			packet.IP.Protocol = &proto
			packet.IP.TOS = &tos
			packet.IP.TTL = &ttl
		case layers.LayerTypeTCP:
			if packet.Transport == nil {
				packet.Transport = new(PacketTransport)
			}
			srcPort := uint16(tcp.SrcPort)
			dstPort := uint16(tcp.DstPort)
			packet.Transport.SrcPort = &srcPort
			packet.Transport.DstPort = &dstPort
		case layers.LayerTypeUDP:
			if packet.Transport == nil {
				packet.Transport = new(PacketTransport)
			}
			srcPort := uint16(udp.SrcPort)
			dstPort := uint16(udp.DstPort)
			packet.Transport.SrcPort = &srcPort
			packet.Transport.DstPort = &dstPort
		}
	}

	if packet.Transport != nil {
		packet.PacketType = "Transport"
	} else if packet.IP != nil {
		packet.PacketType = "IP"
	} else if packet.Ethernet != nil {
		packet.PacketType = "Ethernet"
	} else {
		packet.PacketType = "Unknown"
	}

	return packet, err
}
