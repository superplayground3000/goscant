// File: internal/scanner/scanner.go
package scanner

import (
    "context"
    "net"
    "time"

    "goscant/internal/config"
)

// Status indicates probe outcome.
type Status int

const (
    Open Status = iota
    Closed
    Filtered
    Error
)

// Result captures probe data.
type Result struct {
    IP        string
    Port      int
    Status    Status
    LatencyMS int64
    Err       error
}

// Scanner defines one probe operation.
type Scanner interface {
    Scan(ctx context.Context, ip string, port int) Result
}

// NewFactory returns concrete scanner.
func NewFactory(cfg *config.Config, rawCapable bool) Scanner {
    if rawCapable && !cfg.DryRun {
        return NewRawScanner(cfg)
    }
    return NewSocketScanner(cfg)
}

// CheckRawSocketCapability checks runtime privilege.
func CheckRawSocketCapability() bool {
    // Simple attempt to open raw socket
    conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
    if err != nil { return false }
    conn.Close()
    return true
}

// ------ socket scanner --------

type socketScanner struct {
    timeout time.Duration
    delay   time.Duration
}

func NewSocketScanner(cfg *config.Config) Scanner {
    return &socketScanner{timeout: cfg.Timeout, delay: cfg.Delay}
}

func (s *socketScanner) Scan(ctx context.Context, ip string, port int) Result {
    addr := net.JoinHostPort(ip, strconv.Itoa(port))
    start := time.Now()
    d := net.Dialer{Timeout: s.timeout}
    conn, err := d.DialContext(ctx, "tcp", addr)
    if err != nil {
        if errors.Is(err, context.DeadlineExceeded) {
            return Result{IP: ip, Port: port, Status: Filtered, LatencyMS: s.timeout.Milliseconds(), Err: err}
        }
        return Result{IP: ip, Port: port, Status: Closed, LatencyMS: time.Since(start).Milliseconds(), Err: err}
    }
    conn.Close()
    time.Sleep(s.delay)
    return Result{IP: ip, Port: port, Status: Open, LatencyMS: time.Since(start).Milliseconds()}
}

// ----- raw scanner skeleton -----

func NewRawScanner(cfg *config.Config) Scanner {
    return &rawScanner{cfg: cfg}
}

type rawScanner struct {
    cfg *config.Config
}

func (r *rawScanner) Scan(ctx context.Context, ip string, port int) Result {
    // TODO: implement full SYN, ACK, FIN handshake with gopacket.
    return Result{IP: ip, Port: port, Status: Error, Err: errors.New("raw scanner not implemented")}
}