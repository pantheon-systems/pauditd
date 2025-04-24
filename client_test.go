package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/pantheon-systems/pauditd/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestNetlinkClient_KeepConnection(t *testing.T) {
	n := makeNelinkClient(t)

	n.KeepConnection()
	msg, err := n.Receive()
	if err != nil {
		t.Fatal("Did not expect an error", err)
	}

	expectedData := []byte{4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(expectedData[12:16], uint32(os.Getpid()))

	assert.Equal(t, uint16(1001), msg.Header.Type, "Header.Type mismatch")
	assert.Equal(t, uint16(5), msg.Header.Flags, "Header.Flags mismatch")
	assert.Equal(t, uint32(1), msg.Header.Seq, "Header.Seq mismatch")
	assert.Equal(t, uint32(56), msg.Header.Len, "Packet size is wrong - this test is brittle though")
	assert.EqualValues(t, msg.Data[:40], expectedData, "data was wrong")

	// Make sure we get errors printed
	lb, elb := hookLogger()
	defer resetLogger()
	if err := syscall.Close(n.fd); err != nil {
		t.Errorf("Failed to close syscall fd: %v", err)
	}
	n.KeepConnection()
	assert.Equal(t, "", lb.String(), "Got some log lines we did not expect")

	perr := json.Unmarshal([]byte(elb.Bytes()), &logline)
	if perr != nil {
		fmt.Println("Error unmarshaling logger output JSON:", perr)
	}

	assert.Equal(t, "Error occurred while trying to keep the connection:", logline.Msg, "Figured we would have an error")
}

func TestNetlinkClient_SendReceive(t *testing.T) {
	var err error
	var msg *syscall.NetlinkMessage

	// Build our client
	n := makeNelinkClient(t)
	defer func() {
		if err := syscall.Close(n.fd); err != nil {
			t.Errorf("Failed to close syscall fd: %v", err)
		}
	}()

	// Make sure we can encode/decode properly
	payload := &AuditStatusPayload{
		Mask:    4,
		Enabled: 1,
		Pid:     uint32(1006),
	}

	packet := &NetlinkPacket{
		Type:  uint16(1001),
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		Pid:   uint32(1006),
	}

	// Send and receive the packet
	msg = sendReceive(t, n, packet, payload)

	// Validate the header fields that are not directly encoded to the AuditStatusPayload
	assert.Equal(t, packet.Type, msg.Header.Type, "Header.Type mismatch")
	assert.Equal(t, packet.Flags, msg.Header.Flags, "Header.Flags mismatch")
	assert.Equal(t, uint32(1), msg.Header.Seq, "Header.Seq mismatch")
	assert.Equal(t, uint32(56), msg.Header.Len, "Packet size is wrong - this test is brittle though")

	// Extract the meaningful portion of the data
	meaningfulData := msg.Data[:40]

	// Deserialize syscall.NetlinkMessage{Data} into an AuditStatusPayload
	// AuditStatusPayload is a custom struct that represents the logical
	// structure of the payload one expects to send or receive in a Netlink message.
	// This struct is used to encode or decode the Data field of a syscall.NetlinkMessage.
	var receivedPayload AuditStatusPayload
	dataReader := bytes.NewReader(meaningfulData)
	err = binary.Read(dataReader, binary.LittleEndian, &receivedPayload)
	if err != nil {
		t.Fatalf("Failed to deserialize payload: %v", err)
	}

	// Compare the deserialized payload with the expected payload
	assert.Equal(t, payload.Mask, receivedPayload.Mask, "Payload.Mask mismatch")
	assert.Equal(t, payload.Enabled, receivedPayload.Enabled, "Payload.Enabled mismatch")
	assert.Equal(t, payload.Pid, receivedPayload.Pid, "Payload.Pid mismatch")

	// Make sure sequences numbers increment on our side
	msg = sendReceive(t, n, packet, payload)
	assert.Equal(t, uint32(2), msg.Header.Seq, "Header.Seq did not increment")

	// Make sure 0-length packets result in an error
	if err := syscall.Sendto(n.fd, []byte{}, 0, n.address); err != nil {
		t.Errorf("Failed to send data: %v", err)
	}
	_, err = n.Receive()
	assert.Equal(t, "got a 0 length packet", err.Error(), "Error was incorrect")

	// Make sure we get errors from sendto back
	if err := syscall.Close(n.fd); err != nil {
		t.Errorf("Failed to close syscall fd: %v", err)
	}
	err = n.Send(packet, payload)
	assert.Equal(t, "bad file descriptor", err.Error(), "Error was incorrect")

	// Make sure we get errors from recvfrom back
	n.fd = 0
	_, err = n.Receive()
	assert.Equal(t, "socket operation on non-socket", err.Error(), "Error was incorrect")
}

func TestNewNetlinkClient(t *testing.T) {
	// Hook loggers to capture output
	lb, elb := hookLogger()
	defer resetLogger()

	// Create a new NetlinkClient
	n, err := NewNetlinkClient(1024)
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}
	t.Logf("Received file descriptor: %d", n.fd)

	defer n.Close()

	// Verify the NetlinkClient is properly initialized
	assert.NotNil(t, n, "Expected a netlink client but got nil")
	// In Linux (and UNIX-like systems), file descriptors are:
	//	0 → stdin
	//	1 → stdout
	//	2 → stderr
	//	3+ → other open files/sockets
	assert.GreaterOrEqual(t, n.fd, 0, "Invalid file descriptor")
	assert.NotNil(t, n.address, "Address was nil")
	assert.Equal(t, uint32(0), n.seq, "Seq should start at 0")
	assert.True(t, MaxAuditMessageLength >= len(n.buf), "Client buffer is too small")

	// Verify log output
	assert.Contains(t, lb.String(), "Socket receive buffer size:", "Expected log lines for socket buffer size")
	assert.Equal(t, "", elb.String(), "Did not expect any error messages")
}

// Helper to make a client listening on a unix socket
func makeNelinkClient(t *testing.T) *NetlinkClient {
	if err := os.Remove("pauditd.test.sock"); err != nil && !os.IsNotExist(err) {
		t.Errorf("Failed to remove test socket: %v", err)
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_RAW, 0)
	if err != nil {
		t.Fatal("Could not create a socket:", err)
	}

	n := &NetlinkClient{
		fd:      fd,
		address: &syscall.SockaddrUnix{Name: "pauditd.test.sock"},
		buf:     make([]byte, MaxAuditMessageLength),
	}

	if err = syscall.Bind(fd, n.address); err != nil {
		if err := syscall.Close(fd); err != nil {
			t.Errorf("Failed to close socket fd after bind error: %v", err)
		}
		t.Fatal("Could not bind to netlink socket:", err)
	}

	return n
}

// Helper to send and then receive a message with the netlink client
func sendReceive(t *testing.T, n *NetlinkClient, packet *NetlinkPacket, payload *AuditStatusPayload) *syscall.NetlinkMessage {
	err := n.Send(packet, payload)
	if err != nil {
		t.Fatal("Failed to send:", err)
	}

	msg, err := n.Receive()
	if err != nil {
		t.Fatal("Failed to receive:", err)
	}

	return msg
}

// Resets global loggers
func resetLogger() {
	logger.SetOutput(os.Stdout, "info")
	logger.SetOutput(os.Stderr, "error")
}

// Hooks the global loggers writers so you can assert their contents
func hookLogger() (lb *bytes.Buffer, elb *bytes.Buffer) {
	lb = &bytes.Buffer{}
	logger.SetOutput(lb, "info")

	elb = &bytes.Buffer{}
	logger.SetOutput(elb, "error")
	return
}
