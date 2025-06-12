// File: internal/input/targets.go
package input

import (
    "bufio"
    "context"
    "encoding/csv"
    "net"
    "os"
    "strconv"
    "strings"

    "goscant/internal/config"
    "goscant/internal/ping"
)

// ProbeTarget represents a single IP+port tuple.
type ProbeTarget struct {
    IP   string
    Port int
}

// ParseTargets returns slice of targets after ping filtering.
func ParseTargets(ctx context.Context, cfg *config.Config) ([]ProbeTarget, error) {
    if cfg.ResumeFile != "" {
        return loadCheckpoint(cfg.ResumeFile)
    }

    ips, err := parseIPs(cfg.IPInput)
    if err != nil {
        return nil, err
    }
    ports, err := parsePorts(cfg.PortInput)
    if err != nil {
        return nil, err
    }

    // ping filter
    reachable := make([]string, 0, len(ips))
    for _, ip := range ips {
        ok, _ := ping.Ping(ctx, ip, cfg.Timeout)
        if ok {
            reachable = append(reachable, ip)
        }
    }

    targets := make([]ProbeTarget, 0, len(reachable)*len(ports))
    for _, port := range ports {
        for _, ip := range reachable {
            targets = append(targets, ProbeTarget{IP: ip, Port: port})
        }
    }
    return targets, nil
}

// parseIPs handles IPv4/CIDR/hostname or CSV file.
func parseIPs(arg string) ([]string, error) {
    if strings.HasSuffix(arg, ".csv") {
        f, err := os.Open(arg)
        if err != nil { return nil, err }
        defer f.Close()
        r := csv.NewReader(f)
        _ , _ = r.Read() // skip header
        out := []string{}
        for {
            rec, err := r.Read()
            if err != nil { break }
            cidr := strings.TrimSpace(rec[0])
            ips, _ := cidrExpand(cidr)
            out = append(out, ips...)
        }
        return out, nil
    }
    // simple list separated by comma
    parts := strings.Split(arg, ",")
    out := []string{}
    for _, p := range parts {
        p = strings.TrimSpace(p)
        ips, _ := cidrExpand(p)
        out = append(out, ips...)
    }
    return out, nil
}

func cidrExpand(val string) ([]string, error) {
    // try CIDR
    if strings.Contains(val, "/") {
        ip, ipnet, err := net.ParseCIDR(val)
        if err != nil { return nil, err }
        ips := []string{}
        for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
            ips = append(ips, ip.String())
        }
        return ips, nil
    }
    // hostname or raw IP
    if net.ParseIP(val) != nil {
        return []string{val}, nil
    }
    addrs, _ := net.LookupHost(val)
    return addrs, nil
}

func incIP(ip net.IP) {
    for j := len(ip)-1; j >=0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

func parsePorts(arg string) ([]int, error) {
    if strings.HasSuffix(arg, ".csv") {
        f, err := os.Open(arg)
        if err != nil { return nil, err }
        defer f.Close()
        r := csv.NewReader(f)
        out := []int{}
        for {
            rec, err := r.Read()
            if err != nil { break }
            portProto := strings.Split(rec[1], "/")[0]
            p, _ := strconv.Atoi(portProto)
            out = append(out, p)
        }
        return out, nil
    }
    ports := []int{}
    for _, part := range strings.Split(arg, ",") {
        part = strings.TrimSpace(part)
        if strings.Contains(part, "-") {
            pair := strings.Split(part, "-")
            start, _ := strconv.Atoi(pair[0])
            end, _ := strconv.Atoi(pair[1])
            for p := start; p <= end; p++ {
                ports = append(ports, p)
            }
        } else {
            p, _ := strconv.Atoi(part)
            ports = append(ports, p)
        }
    }
    return ports, nil
}

// TODO: loadCheckpoint implementation placeholder
func loadCheckpoint(path string) ([]ProbeTarget, error) { return nil, nil }