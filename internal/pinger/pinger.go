package pinger

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FilterReachableHosts takes a slice of hosts, pings them concurrently,
// and returns a new slice containing only the hosts that responded.
func FilterReachableHosts(hosts []string, timeout time.Duration, workers int, logger *log.Logger) []string {
	var reachableHosts []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	hostJobChan := make(chan string, len(hosts))
	for _, host := range hosts {
		hostJobChan <- host
	}
	close(hostJobChan)

	logger.Printf("[Pinger] - Starting reachability check for %d hosts with %d workers (timeout: %s)...", len(hosts), workers, timeout)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostJobChan {
				pingCtx, cancel := context.WithTimeout(context.Background(), timeout)

				if Ping(pingCtx, host) {
					mu.Lock()
					reachableHosts = append(reachableHosts, host)
					mu.Unlock()
					logger.Printf("[Pinger] - SUCCESS: Host %s is reachable.", host)
				} else {
					logger.Printf("[Pinger] - INFO: Host %s is unreachable or timed out, skipping.", host)
				}
				cancel()
			}
		}()
	}

	wg.Wait()
	logger.Printf("[Pinger] - Reachability check complete. %d of %d hosts are online.", len(reachableHosts), len(hosts))
	return reachableHosts
}

// Ping returns true if host responds to a single echo request within ctx deadline.
func Ping(ctx context.Context, hostOrIP string) bool {
	// Try raw ICMP first; fall back to system ping when raw not permitted.
	// rawPing requires an IP address. systemPing can often handle hostnames.
	var ipToUseForRawPing net.IP
	parsedIP := net.ParseIP(hostOrIP)

	if parsedIP != nil {
		ipToUseForRawPing = parsedIP
	} else {
		// It's likely a hostname, try to resolve it.
		resolvedIPAddr, err := net.ResolveIPAddr("ip", hostOrIP)
		if err != nil {
			// Resolution failed, fall back to systemPing with the original hostOrIP
			return systemPing(ctx, hostOrIP)
		}
		ipToUseForRawPing = resolvedIPAddr.IP
	}

	if ipToUseForRawPing == nil {
		return systemPing(ctx, hostOrIP)
	}

	ok, err := rawPing(ctx, ipToUseForRawPing.String())
	if err == nil {
		return ok
	}
	// err occurred with rawPing (e.g. permissions, timeout, no reply)
	// Fallback to systemPing.
	// A log message about err from rawPing could be added here if a logger was available.
	return systemPing(ctx, hostOrIP)
}

func systemPing(ctx context.Context, ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// -n 1 (count), -w timeout in ms (example uses 100ms, context handles overall timeout)
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "100", ip)
	} else {
		// -c 1 (count), -W timeout in seconds (example uses 1s, context handles overall timeout)
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run() == nil
}

func rawPing(ctx context.Context, dstIP string) (bool, error) {
	parsedDstIP := net.ParseIP(dstIP)
	if parsedDstIP == nil {
		return false, fmt.Errorf("rawPing: invalid destination IP string: %s", dstIP)
	}

	handle, err := pcap.OpenLive("any", 65535, false, pcap.BlockForever)
	if err != nil {
		return false, fmt.Errorf("rawPing: pcap.OpenLive failed: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("icmp and src host " + parsedDstIP.String()); err != nil {
		return false, fmt.Errorf("rawPing: SetBPFFilter failed: %w", err)
	}

	ipLayer := &layers.IPv4{SrcIP: nil, DstIP: parsedDstIP, Protocol: layers.IPProtocolICMPv4}
	icmpLayer := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 0x1234, Seq: 1}
	payload := gopacket.Payload([]byte("goscant"))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, icmpLayer, payload); err != nil {
		return false, fmt.Errorf("rawPing: SerializeLayers failed: %w", err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return false, fmt.Errorf("rawPing: WritePacketData failed: %w", err)
	}

	pktSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	deadline, _ := ctx.Deadline()
	timeout := time.NewTimer(time.Until(deadline)) // Assumes ctx has a deadline
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timeout.C:
			return false, context.DeadlineExceeded
		case p, ok := <-pktSrc.Packets():
			if !ok {
				return false, fmt.Errorf("rawPing: packet source closed")
			}
			if p == nil { // Should not happen if ok is true, but defensive
				continue
			}
			if receivedICMPLayer := p.Layer(layers.LayerTypeICMPv4); receivedICMPLayer != nil {
				receivedICMP, _ := receivedICMPLayer.(*layers.ICMPv4)
				if receivedICMP.Id == 0x1234 && receivedICMP.Seq == 1 && receivedICMP.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
					return true, nil
				}
			}
		}
	}
}
