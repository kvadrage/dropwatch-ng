package dropmon

import (
	"fmt"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const NET_DM_FAMILY_NAME = "NET_DM"

/* These are the netlink message types for this protocol */

const (
	NET_DM_CMD_UNSPEC = iota
	NET_DM_CMD_ALERT
	NET_DM_CMD_CONFIG
	NET_DM_CMD_START
	NET_DM_CMD_STOP
	NET_DM_CMD_PACKET_ALERT
	NET_DM_CMD_CONFIG_GET
	NET_DM_CMD_CONFIG_NEW
	NET_DM_CMD_STATS_GET
	NET_DM_CMD_STATS_NEW
	NET_DM_CMD_MAX
)

const NET_DM_GRP_ALERT = 1

const (
	NET_DM_ATTR_UNSPEC     = iota
	NET_DM_ATTR_ALERT_MODE /* u8 */
	NET_DM_ATTR_PC         /* u64 */
	NET_DM_ATTR_SYMBOL     /* string */
	NET_DM_ATTR_IN_PORT    /* nested */
	NET_DM_ATTR_TIMESTAMP  /* u64 */
	NET_DM_ATTR_PROTO      /* u16 */
	NET_DM_ATTR_PAYLOAD    /* binary */
	NET_DM_ATTR_PAD
	NET_DM_ATTR_TRUNC_LEN          /* u32 */
	NET_DM_ATTR_ORIG_LEN           /* u32 */
	NET_DM_ATTR_QUEUE_LEN          /* u32 */
	NET_DM_ATTR_STATS              /* nested */
	NET_DM_ATTR_HW_STATS           /* nested */
	NET_DM_ATTR_ORIGIN             /* u16 */
	NET_DM_ATTR_HW_TRAP_GROUP_NAME /* string */
	NET_DM_ATTR_HW_TRAP_NAME       /* string */
	NET_DM_ATTR_HW_ENTRIES         /* nested */
	NET_DM_ATTR_HW_ENTRY           /* nested */
	NET_DM_ATTR_HW_TRAP_COUNT      /* u32 */
	NET_DM_ATTR_SW_DROPS           /* flag */
	NET_DM_ATTR_HW_DROPS           /* flag */
	NET_DM_ATTR_MAX
)

/**
 * enum net_dm_alert_mode - Alert mode.
 * @NET_DM_ALERT_MODE_SUMMARY: A summary of recent drops is sent to user space.
 * @NET_DM_ALERT_MODE_PACKET: Each dropped packet is sent to user space along
 *                            with metadata.
 */
const (
	NET_DM_ALERT_MODE_SUMMARY = iota
	NET_DM_ALERT_MODE_PACKET
)

const (
	NET_DM_ATTR_PORT_NETDEV_IFINDEX = iota /* u32 */
	NET_DM_ATTR_PORT_NETDEV_NAME           /* string */
)

const (
	NET_DM_ATTR_STATS_DROPPED = iota /* u64 */
)

const (
	NET_DM_ORIGIN_SW = iota
	NET_DM_ORIGIN_HW
)

type AlertMsg struct {
	Timestamp time.Time
	Origin    string
	Trap      string
	Group     string
	Port      AlertMsgPort
	Packet    AlertMsgPacket
}

type AlertMsgPort struct {
	InPortIfIndex uint32
	InPortName    string
}

func (p *AlertMsgPort) decode() func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return fmt.Errorf("failed to create nested attribute decoder: %v", err)
		}
		for ad.Next() {
			switch ad.Type() {
			case NET_DM_ATTR_PORT_NETDEV_IFINDEX:
				p.InPortIfIndex = ad.Uint32()
			case NET_DM_ATTR_PORT_NETDEV_NAME:
				p.InPortName = ad.String()
			}
		}
		return ad.Err()
	}
}

type AlertMsgPacket struct {
	Length     uint32
	OrigLength uint32
	Protocol   uint16
	Payload    []byte
}

type DropMon struct {
	conn    *genetlink.Conn
	family  *genetlink.Family
	stopped chan struct{}
	// config struct {
	// 	alertMode uint8
	// 	truncLen uint32
	// 	monitorHW bool
	// 	monitorSW bool
	// }
}

func NewDropMon() *DropMon {
	return &DropMon{}
}

func (dm *DropMon) Init() error {
	var err error
	dm.stopped = make(chan struct{})
	dm.conn, err = genetlink.Dial(nil)
	if err != nil {
		return err
	}

	// Ask generic netlink about Drop Monitor (NET_DM)
	family, err := dm.conn.GetFamily(NET_DM_FAMILY_NAME)
	if err != nil {
		if netlink.IsNotExist(err) {
			return fmt.Errorf("%q family not available", NET_DM_FAMILY_NAME)
		}
		return err
	}
	dm.family = &family

	return nil
}

func (dm *DropMon) Close() {
	if dm.stopped != nil {
		close(dm.stopped)
	}
	dm.conn.Close()
}

func (dm *DropMon) SetAlertMode(mode uint8) error {
	var err error

	encoder := netlink.NewAttributeEncoder()
	encoder.Uint8(NET_DM_ATTR_ALERT_MODE, mode)

	data, err := encoder.Encode()
	if err != nil {
		return fmt.Errorf("Failed to encode message attributes: %v", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: NET_DM_CMD_CONFIG,
			Version: dm.family.Version,
		},
		Data: data,
	}
	flags := netlink.Request | netlink.Acknowledge

	_, err = dm.conn.Execute(req, dm.family.ID, flags)
	if err != nil {
		return fmt.Errorf("failed to execute: %v", err)
	}

	return nil
}

func (dm *DropMon) SetTruncLen(truncLen uint32) error {
	var err error

	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(NET_DM_ATTR_TRUNC_LEN, truncLen)

	data, err := encoder.Encode()
	if err != nil {
		return fmt.Errorf("Failed to encode message attributes: %v", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: NET_DM_CMD_CONFIG,
			Version: dm.family.Version,
		},
		Data: data,
	}
	flags := netlink.Request | netlink.Acknowledge

	_, err = dm.conn.Execute(req, dm.family.ID, flags)
	if err != nil {
		return fmt.Errorf("failed to execute: %v", err)
	}

	return nil
}

func (dm *DropMon) EnableDropMonitor(monitorSW bool, monitorHW bool) error {
	var err error

	encoder := netlink.NewAttributeEncoder()
	if monitorSW {
		encoder.Bytes(NET_DM_ATTR_SW_DROPS, nil)
	}

	if monitorHW {
		encoder.Bytes(NET_DM_ATTR_HW_DROPS, nil)
	}

	data, err := encoder.Encode()
	if err != nil {
		return fmt.Errorf("Failed to encode message attributes: %v", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: NET_DM_CMD_START,
			Version: dm.family.Version,
		},
		Data: data,
	}
	flags := netlink.Request | netlink.Acknowledge

	_, err = dm.conn.Execute(req, dm.family.ID, flags)
	if err != nil {
		return fmt.Errorf("failed to execute: %v", err)
	}

	return nil
}

func (dm *DropMon) DisableDropMonitor(monitorSW bool, monitorHW bool) error {
	var err error

	encoder := netlink.NewAttributeEncoder()
	if monitorSW {
		encoder.Bytes(NET_DM_ATTR_SW_DROPS, nil)
	}

	if monitorHW {
		encoder.Bytes(NET_DM_ATTR_HW_DROPS, nil)
	}

	data, err := encoder.Encode()
	if err != nil {
		return fmt.Errorf("Failed to encode message attributes: %v", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: NET_DM_CMD_STOP,
			Version: dm.family.Version,
		},
		Data: data,
	}
	flags := netlink.Request | netlink.Acknowledge

	_, err = dm.conn.Execute(req, dm.family.ID, flags)
	if err != nil {
		return fmt.Errorf("failed to execute: %v", err)
	}

	return nil
}

func (dm *DropMon) parseOrigin(origin uint16) string {
	switch origin {
	case NET_DM_ORIGIN_SW:
		return "software"
	case NET_DM_ORIGIN_HW:
		return "hardware"
	default:
		return "unknown"
	}
}

func (dm *DropMon) parseTime(unix_time uint64) time.Time {
	return time.Unix(0, int64(unix_time))
}

func (dm *DropMon) decodeAlertMessage(msg *genetlink.Message) (*AlertMsg, error) {
	var err error

	if msg == nil {
		return nil, fmt.Errorf("Message is NIL")
	}

	var alertMsg *AlertMsg

	ad, err := netlink.NewAttributeDecoder(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create attribute decoder: %v", err)
	}
	alertMsg = new(AlertMsg)

	for ad.Next() {
		typ := ad.Type()
		// clear MSB to handle nested attrs
		typ &^= (1 << 15)
		switch typ {
		case NET_DM_ATTR_HW_TRAP_GROUP_NAME:
			alertMsg.Group = ad.String()
		case NET_DM_ATTR_HW_TRAP_NAME:
			alertMsg.Trap = ad.String()
		case NET_DM_ATTR_ORIGIN:
			alertMsg.Origin = dm.parseOrigin(ad.Uint16())
		case NET_DM_ATTR_IN_PORT:
			ad.Do(alertMsg.Port.decode())
		case NET_DM_ATTR_TIMESTAMP:
			alertMsg.Timestamp = dm.parseTime(ad.Uint64())
		case NET_DM_ATTR_PROTO:
			alertMsg.Packet.Protocol = ad.Uint16()
		case NET_DM_ATTR_ORIG_LEN:
			alertMsg.Packet.OrigLength = ad.Uint32()
		case NET_DM_ATTR_PAYLOAD:
			payload := ad.Bytes()
			alertMsg.Packet.Length = uint32(len(payload))
			alertMsg.Packet.Payload = payload
		}
	}

	if err := ad.Err(); err != nil {
		return nil, fmt.Errorf("failed to decode attributes: %v", err)
	}

	return alertMsg, nil
}

func (dm *DropMon) Start(ch chan *AlertMsg) error {
	var err error

	if ch == nil {
		return fmt.Errorf("AlertMsg channel is NIL")
	}
	err = dm.conn.JoinGroup(NET_DM_GRP_ALERT)
	if err != nil {
		return fmt.Errorf("Failed to join NET_DM_GRP_ALERT group: %v", err)
	}
	go func() {
		fmt.Println("= Drop monitor started")
		defer func() {
			close(ch)
			dm.conn.LeaveGroup(NET_DM_GRP_ALERT)
			fmt.Println("= Drop monitor stopped")
		}()
		for {
			select {
			case <-dm.stopped:
				// process stop signal
				return
			default:
				msgs, _, err := dm.conn.Receive()
				if err != nil {
					return
				}

				for _, msg := range msgs {
					alertMsg, err := dm.decodeAlertMessage(&msg)
					if err != nil {
						fmt.Printf("decodeAlertMessage error: %v\n", err)
					}
					ch <- alertMsg
				}

			}
		}
	}()
	return nil
}

func (dm *DropMon) Stop() {
	dm.stopped <- struct{}{}
}
