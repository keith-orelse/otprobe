// otprobe-agent: OTProbe's read-only compliance agent.
//
//	otprobe-agent run [--config PATH]      run in the foreground (or under the service manager with --service)
//	otprobe-agent install [--config PATH]  register the OS service (called by install.ps1 / install.sh)
//	otprobe-agent uninstall | start | stop | status
//	otprobe-agent collect                  print the evidence every compiled-in collector gathers (dry run)
//	otprobe-agent version | fingerprint
//
// Exit codes: 0 ok, 1 error, 3 credential revoked (the service is disabled and stays stopped).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"otprobe/agent/internal/agent"
	"otprobe/agent/internal/collectors"
	"otprobe/agent/internal/config"
	"otprobe/agent/internal/service"
	"otprobe/agent/internal/transport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "path to agent.json")
	_ = fs.Bool("service", false, "started by the service manager")
	_ = fs.Parse(os.Args[2:])

	var err error
	switch cmd {
	case "run":
		err = runAgent(*cfgPath)
	case "install":
		exe, _ := os.Executable()
		err = service.Install(exe, *cfgPath, filepath.Dir(*cfgPath))
	case "uninstall":
		err = service.Uninstall()
	case "start":
		err = service.Start()
	case "stop":
		err = service.Stop()
	case "status":
		var st string
		st, err = service.Status()
		fmt.Println(st)
	case "collect":
		sections, status := collectors.Run(context.Background(), collectors.Names())
		sections["collectors"] = status
		out, _ := json.MarshalIndent(sections, "", "  ")
		fmt.Println(string(out))
	case "version":
		fmt.Printf("otprobe-agent %s (%s/%s, %s build, %s)\n", collectors.Version, runtime.GOOS, runtime.GOARCH,
			agent.Variant, runtime.Version())
	case "fingerprint":
		fmt.Println(collectors.Fingerprint())
	default:
		usage()
		os.Exit(1)
	}
	if errors.Is(err, transport.ErrRevoked) {
		log.Printf("credential revoked by the server: disabling the service until the agent is reinstalled")
		service.DisableSelf()
		os.Exit(3)
	}
	if err != nil {
		log.Printf("%s: %v", cmd, err)
		os.Exit(1)
	}
}

func runAgent(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading %s: %w", cfgPath, err)
	}
	a, err := agent.New(cfg)
	if err != nil {
		return err
	}
	log.Printf("otprobe-agent %s starting (%s/%s, server %s)", collectors.Version, runtime.GOOS, runtime.GOARCH,
		cfg.ServerURL)
	return service.RunService(a.Run)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: otprobe-agent run|install|uninstall|start|stop|status|collect|version|fingerprint "+
		"[--config PATH]")
}
