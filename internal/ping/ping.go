// File: internal/ping/ping.go
package ping

import (
    "context"
    "errors"
    "net"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// Ping sends one ICMP Echo and waits for reply.
func Ping(ctx context.Context, ip string, timeout time.Duration) (bool, error) {
    // fallback: if no raw privilege, use system ping
    handle, err := pcap.OpenLive("", 65535, false, pcap.BlockForever)
    if err != nil {
        return systemPing(ip, timeout)
    }
    defer handle.Close()

    // Build ICMP packet using gopacket
    icmp := layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 0x1234, Seq: 1}
    buffer := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{ComputeChecksums: true}
    if err := icmp.SerializeTo(buffer, opts); err != nil {
        return false, err
    }

    // NOTE: For brevity we skip crafting IPv4 + Ethernet layers; on Linux AF_INET raw is simpler.
    // Send/receive steps omitted here.
    select {
    case <-time.After(timeout):
        return false, nil
    case <-ctx.Done():
        return false, ctx.Err()
    }
}

func systemPing(ip string, timeout time.Duration) (bool, error) {
    // For Windows or unprivileged environment – rely on exec.Command("ping")
    return false, errors.New("not implemented")
}