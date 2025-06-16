# goscant

**goscant** is a high-performance, concurrent TCP port scanner written in Go. It supports both TCP Connect and SYN scan modes, offers flexible input options, and is designed for reliability and speed. The tool leverages Go's goroutines for massive parallelism and efficient resource usage.

> **Attention:** SYN scanner functionality has been removed since Go's net package already handles TCP three-way handshake properly.

## Features

- **Concurrent scanning** with configurable worker pool
- **TCP Connect** and **SYN Stealth** scan modes
- **Pre-scan ICMP ping** to filter unreachable hosts (optional)
- **Resume** interrupted scans from a checkpoint
- **CSV output** for easy result analysis
- **Detailed logging** with configurable log levels
- **Graceful shutdown** and checkpointing on interrupt

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/goscant.git
   cd goscant
   ```

2. **Build the binary:**

   ```bash
   go build -o goscant main.go
   ```

3. **(Optional) Install dependencies:**

   ```bash
   go mod tidy
   ```

## Usage

```bash
./goscant --ip <IP/CIDR/host/file> --port <ports/range/file> [flags]
```

### Required Flags

- `--ip`  
  IPv4 address, CIDR, hostname, or a file (CSV/TXT) with IP/host info.

- `--port`  
  Port(s) to scan. Accepts single ports (80), ranges (8000-8100), or a file.

### Common Flags

- `--worker`  
  Number of concurrent worker threads (default: 1).

- `--timeout`  
  Connection and ping timeout in milliseconds (default: 100).

- `--delay`  
  Delay between probes in milliseconds (default: 100).

- `--queue`  
  Task queue size (default: workers * 1024).

- `--dryrun`  
  Perform a dry run without sending packets.

- `--resume`  
  Resume scan from a checkpoint file.

- `--output`  
  Output file for scan results (default: `results.csv`).

- `--scantype`  
  Scan type: `connect` (default) or `syn`.

- `--ping`  
  Enable pre-scan ICMP check (default: true).

- `--loglevel`  
  Logging level: `DEBUG`, `INFO`, `WARN`, `ERROR` (default: `INFO`).

### Example

```bash
./goscant --ip 192.168.1.0/24 --port 22,80,443 --worker 100 --timeout 200 --scantype connect --output scan.csv
```

## How Port Scanning Works

### Goroutine-based Concurrency

- The scanner uses a **worker pool** model, where each worker is a goroutine.
- Targets (IP:Port pairs) are distributed to workers via a channel (`taskQueue`).
- Each worker pulls a target, performs the scan, and sends the result to a results channel (`resultsChan`).
- Results are written to a CSV file by a dedicated reporter goroutine.

### Scan Types

- **TCP Connect Scan:**  
  Attempts a full TCP handshake using Go's `net.Dialer`. If the connection succeeds, the port is open. If it fails, the port is closed or filtered.

- **SYN Scan (Stealth):**  
  (Requires root privileges) Sends a TCP SYN packet and waits for a response. If a SYN-ACK is received, the port is open. If RST or no response, the port is closed or filtered.

### Execution Flow

1. **Configuration Loading:**  
   Parses command-line flags and validates input.

2. **Target Preparation:**  
   - Parses IPs and ports.
   - Optionally pings hosts to filter unreachable ones.
   - Generates a list of scan targets.

3. **Resuming (if applicable):**  
   If a checkpoint file is provided, resumes from the last saved state.

4. **Worker Pool Launch:**  
   Spawns N worker goroutines for scanning.

5. **Scanning:**  
   - Each worker scans targets concurrently.
   - Results are sent to the reporter goroutine.

6. **Reporting:**  
   The reporter writes results to a CSV file in real time.

7. **Graceful Shutdown:**  
   On interrupt (Ctrl+C), the scanner saves remaining targets to a checkpoint file for resuming later.

## Output

Results are saved in CSV format (default: `results.csv`):

| timestamp           | dst_ip      | dst_port | status   | latency_ms |
|---------------------|-------------|----------|----------|------------|
| 2024-06-01T12:00:00 | 192.168.1.1 | 22       | OPEN     | 10.5       |
| ...                 | ...         | ...      | ...      | ...        |

## License

This project is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
