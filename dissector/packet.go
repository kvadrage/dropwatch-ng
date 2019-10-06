package dissector


type Packet struct {
	PacketType 	string				`json:"packetType"`
	Ethernet	*PacketEthernet		`json:"ETHERNET,omitempty"`
	IP			*PacketIP			`json:"IP,omitempty"`
	Transport 	*PacketTransport	`json:"Transport,omitempty"`
}

type PacketEthernet struct {
	SrcMAC 		*string				`json:"srcMac,omitempty"`
	DstMAC 		*string				`json:"dstMac,omitempty"`
	EtherType 	*uint16				`json:"etherType,omitempty"`
	PCP			*uint8				`json:"pcp,omitempty"`
	VlanID		*uint16				`json:"vlanId,omitempty"`
}

type PacketIP struct {
	SrcIP		*string				`json:"srcIp,omitempty"`
	DstIP		*string				`json:"dstIp,omitempty"`
	Protocol	*uint16				`json:"protocol,omitempty"`
	TOS			*uint8				`json:"tos,omitempty"`
	TTL			*uint8				`json:"ttl,omitempty"`
}

type PacketTransport struct {
	SrcPort		*uint16				`json:"srcPort,omitempty"`
	DstPort		*uint16				`json:"dstPort,omitempty"`
}