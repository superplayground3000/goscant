package scanner

import (
	"fmt"
	"log"
	"net"
	"port-scanner/internal/models"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SynScanner implements the Scanner interface using a raw socket and gopacket.
type SynScanner struct {
	Timeout time.Duration
	Logger  *log.Logger
	SrcPort int
}

// NewSynScanner creates a new instance of a SynScanner.
func NewSynScanner(timeout time.Duration, logger *log.Logger, srcPort int) *SynScanner {
	return &SynScanner{
		Timeout: timeout,
		Logger:  logger,
		SrcPort: srcPort,
	}
}

// Scan performs a SYN scan on a single target port.
func (s *SynScanner) Scan(target models.ScanTarget) models.ScanResult {
	startTime := time.Now()
	result := models.ScanResult{
		Timestamp: startTime,
		Target:    target,
	}

	dstIP := net.ParseIP(target.IP)
	if dstIP == nil {
		result.Status = models.StatusError
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
		result.Status = models.StatusError
		result.Error = fmt.Errorf("failed to serialize packet: %w", err)
		return result
	}

	// 4. Listen for response and send packet
	listen, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		result.Status = models.StatusError
		result.Error = fmt.Errorf("listener failed: %w", err)
		return result
	}
	defer listen.Close()

	if _, err := listen.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
		result.Status = models.StatusError
		result.Error = fmt.Errorf("packet write failed: %w", err)
		return result
	}

	// 5. Wait for reply
	if err := listen.SetReadDeadline(time.Now().Add(s.Timeout)); err != nil {
		result.Status = models.StatusError
		result.Error = fmt.Errorf("deadline set failed: %w", err)
		return result
	}

	replyBuf := make([]byte, 4096)
	for {
		n, addr, err := listen.ReadFrom(replyBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.Status = models.StatusFiltered
			} else {
				result.Status = models.StatusError
				result.Error = err
			}
			break
		}

		if addr.String() == dstIP.String() {
			packet := gopacket.NewPacket(replyBuf[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
				if tcp.DstPort == srcPort {
					if tcp.SYN && tcp.ACK {
						result.Status = models.StatusOpen
					} else if tcp.RST {
						result.Status = models.StatusClosed
					}
					break
				}
			}
		}
	}

	result.Latency = time.Since(startTime)
	return result
}
