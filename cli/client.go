package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"agentguard/daemon"
)

// maxResponseBytes bounds one line read back from the daemon.
const maxResponseBytes = 4 << 20

// Client is a minimal synchronous client for the daemon's line-delimited
// JSON socket protocol (see daemon/socket_api.go), used by every CLI
// subcommand that needs to reach a running daemon (audit, approve, deny).
type Client struct {
	conn    net.Conn
	scanner *bufio.Scanner
}

// Dial connects to the daemon listening on socketPath.
func Dial(socketPath string) (*Client, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to agentguard daemon at %s: %w (is it running? try `agentctl daemon start`)", socketPath, err)
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), maxResponseBytes)
	return &Client{conn: conn, scanner: sc}, nil
}

// Call sends req and returns the daemon's response.
func (c *Client) Call(req daemon.Request) (daemon.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return daemon.Response{}, fmt.Errorf("marshaling request: %w", err)
	}
	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		return daemon.Response{}, fmt.Errorf("writing to daemon: %w", err)
	}
	if !c.scanner.Scan() {
		if err := c.scanner.Err(); err != nil {
			return daemon.Response{}, fmt.Errorf("reading from daemon: %w", err)
		}
		return daemon.Response{}, fmt.Errorf("daemon closed the connection without responding")
	}
	var resp daemon.Response
	if err := json.Unmarshal(c.scanner.Bytes(), &resp); err != nil {
		return daemon.Response{}, fmt.Errorf("parsing daemon response: %w", err)
	}
	return resp, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
