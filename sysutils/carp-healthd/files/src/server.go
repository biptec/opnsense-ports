package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func serveStatusSocket(ctx context.Context, path string, cfg Config, controller *Controller) error {
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go handleStatusConn(conn, cfg, controller)
	}
}

func handleStatusConn(conn net.Conn, cfg Config, controller *Controller) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	command := strings.TrimSpace(line)
	state := controller.Snapshot()
	state.Running = true
	if !stateIsCurrent(cfg, state, time.Now()) {
		state = staleStatus(cfg, true)
	}
	switch command {
	case "status":
		data, err := marshalState(state)
		if err != nil {
			return
		}
		_, _ = conn.Write(append(data, '\n'))
	case "check-global":
		_, _ = fmt.Fprintf(conn, "%d\n", globalExitCode(cfg, state, time.Now()))
	default:
		_, _ = conn.Write([]byte("{\"status\":\"failed\",\"error\":\"unknown command\"}\n"))
	}
}

func socketStatus(path string) (RuntimeState, error) {
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return RuntimeState{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("status\n")); err != nil {
		return RuntimeState{}, err
	}
	var wire wireRuntimeState
	if err := json.NewDecoder(conn).Decode(&wire); err != nil {
		return RuntimeState{}, err
	}
	return fromWireState(wire), nil
}

func socketGlobalExit(path string) (int, error) {
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return 1, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("check-global\n")); err != nil {
		return 1, err
	}
	var code int
	if _, err := fmt.Fscan(conn, &code); err != nil {
		return 1, err
	}
	return code, nil
}
