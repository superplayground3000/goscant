package scanner

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"os"
	"port-scanner/internal/models"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func setupSynTestLogger() (*slog.Logger, *bytes.Buffer) {
	var logBuf bytes.Buffer
	handler := slog.NewTextHandler(io.MultiWriter(&logBuf, os.Stdout), &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	return logger, &logBuf
}

// mockPacketConn for SynScanner tests
type mockPacketConn struct {
	net.PacketConn // Embed to satisfy the interface easily

	readFromFunc        func(p []byte) (n int, addr net.Addr, err error)
	writeToData         []byte
	closeFunc           func() error
	setReadDeadlineFunc func(t time.Time) error
	localAddrFunc       func() net.Addr
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if m.readFromFunc != nil {
		return m.readFromFunc(p)
	}
	return 0, nil, io.EOF // Default behavior
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.writeToData = append(m.writeToData, p...) // Store a copy
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	if m.localAddrFunc != nil {
		return m.localAddrFunc()
	}
	return &net.IPAddr{IP: net.ParseIP("0.0.0.0")}
}

func (m *mockPacketConn) SetDeadline(t time.Time) error { return m.SetReadDeadline(t) }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	if m.setReadDeadlineFunc != nil {
		return m.setReadDeadlineFunc(t)
	}
	return nil
}
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// Backup original functions and restore them after tests
var (
	originalNetListenPacket = netListenPacket
	originalNetDial         = netDialSyn // Specific to SynScanner's source IP discovery
)

func mockNetDialSyn(network, address string) (net.Conn, error) {
	// Return a mock connection that provides a LocalAddr
	return &mockConn{localAddr: &net.UDPAddr{IP: net.ParseIP("192.168.0.100"), Port: 12345}}, nil
}

type mockConn struct {
	net.Conn
	localAddr net.Addr
}

func (m *mockConn) LocalAddr() net.Addr { return m.localAddr }
func (m *mockConn) Close() error        { return nil }

func TestSynScanner_Scan(t *testing.T) {
	logger, logBuf := setupTestLogger()
	srcPort := 12345
	scanner := NewSynScanner(100*time.Millisecond, logger, srcPort)

	// Override net.ListenPacket for the duration of this test
	// and net.Dial for source IP discovery
	netDialSyn = mockNetDialSyn
	defer func() { netDialSyn = originalNetDial }()

	tests := []struct {
		name           string
		targetIP       string
		targetPort     int
		mockReadFrom   func(p []byte) (n int, addr net.Addr, err error)
		expectedStatus models.ScanStatus
		expectError    bool
	}{
		{
			name:       "Open Port (SYN-ACK)",
			targetIP:   "192.0.2.1", // TEST-NET-1
			targetPort: 80,
			mockReadFrom: func(p []byte) (int, net.Addr, error) {
				// Construct a SYN-ACK packet
				tcpLayer := &layers.TCP{
					SrcPort: layers.TCPPort(80),
					DstPort: layers.TCPPort(srcPort),
					SYN:     true,
					ACK:     true,
					Ack:     1105024979, // Seq + 1
					Seq:     uint32(time.Now().Unix()),
				}
				ipLayer := &layers.IPv4{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.168.0.100")} // DstIP is our mocked srcIP
				tcpLayer.SetNetworkLayerForChecksum(ipLayer)
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
				gopacket.SerializeLayers(buf, opts, tcpLayer) // Only TCP layer for simplicity in mock
				copy(p, buf.Bytes())
				return len(buf.Bytes()), &net.IPAddr{IP: net.ParseIP("192.0.2.1")}, nil
			},
			expectedStatus: models.StatusOpen,
		},
		{
			name:       "Closed Port (RST)",
			targetIP:   "192.0.2.2",
			targetPort: 22,
			mockReadFrom: func(p []byte) (int, net.Addr, error) {
				tcpLayer := &layers.TCP{SrcPort: layers.TCPPort(22), DstPort: layers.TCPPort(srcPort), RST: true}
				ipLayer := &layers.IPv4{SrcIP: net.ParseIP("192.0.2.2"), DstIP: net.ParseIP("192.168.0.100")}
				tcpLayer.SetNetworkLayerForChecksum(ipLayer)
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
				gopacket.SerializeLayers(buf, opts, tcpLayer)
				copy(p, buf.Bytes())
				return len(buf.Bytes()), &net.IPAddr{IP: net.ParseIP("192.0.2.2")}, nil
			},
			expectedStatus: models.StatusClosed,
		},
		{
			name:       "Filtered Port (Timeout)",
			targetIP:   "192.0.2.3",
			targetPort: 443,
			mockReadFrom: func(p []byte) (int, net.Addr, error) {
				return 0, nil, os.ErrDeadlineExceeded // Simulate timeout
			},
			expectedStatus: models.StatusFiltered,
		},
		{
			name:           "Invalid Target IP",
			targetIP:       "invalid-ip-address",
			targetPort:     80,
			expectedStatus: models.StatusError,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuf.Reset() // Reset log buffer for each test

			// Setup mock for net.ListenPacket
			mockPC := &mockPacketConn{readFromFunc: tt.mockReadFrom}
			netListenPacket = func(network, address string) (net.PacketConn, error) {
				return mockPC, nil // Return our mock packet conn
			}
			defer func() { netListenPacket = originalNetListenPacket }()

			target := models.ScanTarget{IP: tt.targetIP, Port: tt.targetPort}
			result := scanner.Scan(target)

			if result.Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s. Logs:\n%s", tt.expectedStatus, result.Status, logBuf.String())
			}

			if tt.expectError && result.Error == nil {
				t.Errorf("Expected an error, but got nil")
			}
			if !tt.expectError && result.Error != nil {
				t.Errorf("Expected no error, but got: %v", result.Error)
			}

			// Basic log checks
			if !strings.Contains(logBuf.String(), "Starting SYN scan") && tt.targetIP != "invalid-ip-address" {
				t.Errorf("Expected 'Starting SYN scan' in logs. Logs:\n%s", logBuf.String())
			}
			if tt.expectedStatus == models.StatusOpen && !strings.Contains(logBuf.String(), "Target OPEN (SYN-ACK received)") {
				t.Errorf("Expected 'Target OPEN' log for open port. Logs:\n%s", logBuf.String())
			}
		})
	}
}

// Note: netListenPacket and netDialSyn are package-level variables in syn_scanner.go
// to allow mocking. If they are not, you'd need to use build tags or interfaces
// for dependency injection for these net functions.
// For example, in syn_scanner.go:
// var netListenPacket = net.ListenPacket
// var netDialSyn = net.Dial
