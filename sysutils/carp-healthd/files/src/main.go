package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	fs := flag.NewFlagSet("carp-healthd", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "OPNsense configuration path")
	statePath := fs.String("state", defaultStatePath, "persistent ownership state path")
	socketPath := fs.String("socket", defaultSocketPath, "runtime status socket path")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	command := "run"
	if fs.NArg() > 0 {
		command = fs.Arg(0)
	}

	switch command {
	case "run":
		cfg, err := loadConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		platform, err := newNativePlatform()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer platform.Close()

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		controller := NewController(cfg, platform, *statePath)

		socketErr := make(chan error, 1)
		go func() {
			socketErr <- serveStatusSocket(ctx, *socketPath, cfg, controller)
		}()
		runErr := make(chan error, 1)
		go func() {
			runErr <- controller.Run(ctx)
		}()

		select {
		case err := <-socketErr:
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				stop()
				<-runErr
				return 1
			}
		case err := <-runErr:
			stop()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		case <-ctx.Done():
			<-runErr
		}
		return 0

	case "status":
		cfg, err := loadConfig(*configPath)
		if err != nil {
			printFailure(err)
			return 1
		}
		state, err := socketStatus(*socketPath)
		if err != nil {
			state = staleStatus(cfg, false)
		}
		data, err := marshalState(state)
		if err != nil {
			printFailure(err)
			return 1
		}
		fmt.Println(string(data))
		return 0

	case "check-global":
		cfg, err := loadConfig(*configPath)
		if err != nil {
			return 1
		}
		if code, err := socketGlobalExit(*socketPath); err == nil {
			return code
		}
		return globalExitCode(cfg, staleStatus(cfg, false), time.Now())

	case "reset-actions":
		state, err := readPersistedState(*statePath)
		if err != nil {
			if os.IsNotExist(err) {
				return 0
			}
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		platform, err := newNativePlatform()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer platform.Close()
		if err := resetOwnedActions(platform, state); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0

	case "version":
		fmt.Println(version)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "usage: carp-healthd [flags] {run|status|check-global|reset-actions|version}\n")
		return 64
	}
}

func printFailure(err error) {
	payload := map[string]any{"status": "failed", "error": err.Error()}
	data, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		fmt.Println("{\"status\":\"failed\"}")
		return
	}
	fmt.Println(string(data))
}
