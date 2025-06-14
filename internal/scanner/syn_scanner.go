package scanner

import (
	"fmt"
	"log/slog"
	"net"
	"port-scanner/internal/models"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SynScanner implements the Scanner interface using a raw socket and gopacket.
type SynScanner struct {
	Timeout time.Duration
	Logger  *slog.Logger
	SrcPort int
}

// NewSynScanner creates a new instance of a SynScanner.
func NewSynScanner(timeout time.Duration, logger *slog.Logger, srcPort int) *SynScanner {
	return &SynScanner{
		Timeout: timeout,
		Logger:  logger,
		SrcPort: srcPort,
	}
}

// Scan performs a SYN scan on a single target port.
func (s *SynScanner) Scan(target models.ScanTarget) models.ScanResult {
	s.Logger.Debug("Starting SYN scan", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "src_port", s.SrcPort)
	startTime := time.Now()
	result := models.ScanResult{
		Timestamp: startTime,
		Target:    target,
	}
	dstIP := net.ParseIP(target.IP)
	if dstIP == nil {
		result.Status = models.StatusError
		s.Logger.Error("Invalid destination IP", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "invalid_ip", target.IP)
		result.Error = fmt.Errorf("invalid destination IP: %s", target.IP)
		return result
	}
	dstIP = dstIP.To4() // Ensure IPv4

	// 1. Create TCP Layer
	srcPort := layers.TCPPort(s.SrcPort)
	dstPort := layers.TCPPort(target.Port)
	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
		Window:  1024,
		Seq:     1105024978, // Arbitrary sequence number
	}

	// 2. Create IP Layer
	// We need the source IP to be the one on the interface that can reach the target.
	// This can be complex. For simplicity, we let the kernel decide by dialing.
	conn, err := net.Dial("udp", target.IP+":80")
	if err != nil {
		s.Logger.Error("Could not get source IP", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "error", err)
		result.Status = models.StatusError
		result.Error = fmt.Errorf("could not get source IP: %w", err)
		return result
	}
	srcIP := conn.LocalAddr().(*net.UDPAddr).IP
	conn.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// 3. Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer); err != nil {
		s.Logger.Error("Failed to serialize packet", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "error", err)
		result.Status = models.StatusError
		result.Error = fmt.Errorf("failed to serialize packet: %w", err)
		return result
	}

	// 4. Listen for response and send packet
	listen, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		s.Logger.Error("Listener failed", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "error", err)
		result.Status = models.StatusError
		result.Error = fmt.Errorf("listener failed: %w", err)
		return result
	}
	defer listen.Close()

	if _, err := listen.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
		s.Logger.Error("Packet write failed", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "error", err)
		result.Status = models.StatusError
		result.Error = fmt.Errorf("packet write failed: %w", err)
		return result
	}

	// 5. Wait for reply
	if err := listen.SetReadDeadline(time.Now().Add(s.Timeout)); err != nil {
		s.Logger.Error("Deadline set failed", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "error", err)
		result.Status = models.StatusError

		result.Error = fmt.Errorf("deadline set failed: %w", err)
		return result
	}

	replyBuf := make([]byte, 4096)
	for {
		n, addr, err := listen.ReadFrom(replyBuf)
		s.Logger.Debug("ReadFrom listener", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "bytes_read", n, "from_addr", addr, "error", err)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.Status = models.StatusFiltered
				s.Logger.Debug("Target filtered (timeout on read)", "scanner", "SynScanner", "ip", target.IP, "port", target.Port)
			} else {
				result.Status = models.StatusError
				result.Error = err
				s.Logger.Error("Error reading from listener", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "error", err)
			}
			break
		}

		if addr.String() == dstIP.String() {
			packet := gopacket.NewPacket(replyBuf[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
				if tcp.DstPort == srcPort {
					if tcp.SYN && tcp.ACK {
						result.Status = models.StatusOpen
						s.Logger.Debug("Target OPEN (SYN-ACK received)", "scanner", "SynScanner", "ip", target.IP, "port", target.Port)
					} else if tcp.RST {
						result.Status = models.StatusClosed
						s.Logger.Debug("Target CLOSED (RST received)", "scanner", "SynScanner", "ip", target.IP, "port", target.Port)
					}
					break
				} else {
					s.Logger.Debug("Received TCP packet on wrong DstPort", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "received_dst_port", tcp.DstPort, "expected_dst_port", srcPort)
				}
			}
		}
	}

	result.Latency = time.Since(startTime)
	s.Logger.Debug("Finished SYN scan", "scanner", "SynScanner", "ip", target.IP, "port", target.Port, "status", result.Status, "latency", result.Latency)
	return result
}
