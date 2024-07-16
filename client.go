package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/slog"
)

// Endianness is an alias for what we assume is the current machine endianness
var Endianness = binary.LittleEndian

const (
	// MAX_AUDIT_MESSAGE_LENGTH see http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L398
	MAX_AUDIT_MESSAGE_LENGTH = 8970
)

// TODO: this should live in a marshaller
type AuditStatusPayload struct {
	Mask            uint32
	Enabled         uint32
	Failure         uint32
	Pid             uint32
	RateLimit       uint32
	BacklogLimit    uint32
	Lost            uint32
	Backlog         uint32
	Version         uint32
	BacklogWaitTime uint32
}

// NetlinkPacket is an alias to give the header a similar name here
type NetlinkPacket syscall.NlMsghdr

type NetlinkClient struct {
	fd                   int
	address              syscall.Sockaddr
	seq                  uint32
	buf                  []byte
	cancelKeepConnection chan struct{}
}

// NewNetlinkClient creates a new NetLinkClient and optionally tries to modify the netlink recv buffer
func NewNetlinkClient(recvSize int) (*NetlinkClient, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("Could not create a socket: %s", err)
	}

	n := &NetlinkClient{
		fd:                   fd,
		address:              &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 0, Pid: 0},
		cancelKeepConnection: make(chan struct{}),
	}

	if err = syscall.Bind(fd, n.address); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("Could not bind to netlink socket: %s", err)
	}

	// Set the buffer size if we were asked
	if recvSize > 0 {
		if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvSize); err != nil {
			slog.Error.Println("Failed to set receive buffer size")
		}
	}

	// Print the current receive buffer size
	if v, err := syscall.GetsockoptInt(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
		slog.Info.Println("Socket receive buffer size:", v)
	}

	go func() {
		for {
			select {
			case <-n.cancelKeepConnection:
				return
			default:
				n.KeepConnection()
				time.Sleep(time.Second * 5)
			}
		}
	}()

	return n, nil
}

// Send will send a packet and payload to the netlink socket without waiting for a response
func (n *NetlinkClient) Send(np *NetlinkPacket, a *AuditStatusPayload) error {
	//We need to get the length first. This is a bit wasteful, but requests are rare so yolo..
	buf := new(bytes.Buffer)
	var length int

	np.Seq = atomic.AddUint32(&n.seq, 1)

	for {
		buf.Reset()
		binary.Write(buf, Endianness, np)
		binary.Write(buf, Endianness, a)
		if np.Len == 0 {
			length = len(buf.Bytes())
			np.Len = uint32(length)
		} else {
			break
		}
	}

	if err := syscall.Sendto(n.fd, buf.Bytes(), 0, n.address); err != nil {
		return err
	}

	return nil
}

// Receive will receive a packet from a netlink socket
func (n *NetlinkClient) Receive() (*syscall.NetlinkMessage, error) {
	// Large message handling
	// See https://mdlayher.com/blog/linux-netlink-and-go-part-1-netlink/
	// Use a new buffer every time since this is spawned in a goroutine
	buf := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
	for {
		// Peek at the buffer to see how many bytes are available.
		b, _, err := syscall.Recvfrom(n.fd, buf, syscall.MSG_PEEK)
		if err != nil {
			return nil, err
		}

		// Break when we can read all messages.
		if b < len(buf) {
			break
		}

		// Double in size if not enough bytes.
		buf = make([]byte, len(buf)*2)
	}

	// Read out all available messages.
	nlen, _, err := syscall.Recvfrom(n.fd, buf, 0)
	if err != nil {
		return nil, err
	}

	if nlen < 1 {
		return nil, errors.New("Got a 0 length packet")
	}

	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   Endianness.Uint32(buf[0:4]),
			Type:  Endianness.Uint16(buf[4:6]),
			Flags: Endianness.Uint16(buf[6:8]),
			Seq:   Endianness.Uint32(buf[8:12]),
			Pid:   Endianness.Uint32(buf[12:16]),
		},
		Data: buf[syscall.SizeofNlMsghdr:nlen],
	}

	return msg, nil
}

// KeepConnection re-establishes our connection to the netlink socket
func (n *NetlinkClient) KeepConnection() {
	payload := &AuditStatusPayload{
		Mask:    4,
		Enabled: 1,
		Pid:     uint32(syscall.Getpid()),
		//TODO: Failure: http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L338
	}

	packet := &NetlinkPacket{
		Type:  uint16(1001),
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		Pid:   uint32(syscall.Getpid()),
	}

	err := n.Send(packet, payload)
	if err != nil {
		slog.Error.Println("Error occurred while trying to keep the connection:", err)
	}
}

// Close will stop running goroutines
func (n *NetlinkClient) Close() {
	close(n.cancelKeepConnection)
}
