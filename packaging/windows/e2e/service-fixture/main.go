//go:build windows

// paperboat-windows-service-fixture is used only by the native qualification
// suite. It is a real Windows service process, so the SCM tests exercise the
// same service-manager boundary as Paperboat without modifying a product
// binary or depending on enrollment credentials.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows/svc"
)

type fixtureService struct {
	marker string
	mu     sync.Mutex
}

func (s *fixtureService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	s.appendMarker("running")
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			statuses <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			statuses <- svc.Status{State: svc.StopPending, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			s.appendMarker("stopped")
			statuses <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

func (s *fixtureService) appendMarker(value string) {
	if s.marker == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(s.marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintln(file, value)
}

func main() {
	name, marker, err := parseArguments(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := svc.Run(name, &fixtureService{marker: marker}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseArguments(args []string) (string, string, error) {
	var name, marker, definition string
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--service-name":
			if index+1 >= len(args) {
				return "", "", errors.New("--service-name requires a value")
			}
			name = args[index+1]
			index++
		case "--service-definition":
			if index+1 >= len(args) {
				return "", "", errors.New("--service-definition requires a value")
			}
			definition = args[index+1]
			index++
		case "--marker":
			if index+1 >= len(args) {
				return "", "", errors.New("--marker requires a value")
			}
			marker = args[index+1]
			index++
		}
	}
	if name == "" && definition != "" {
		name = strings.TrimSuffix(filepath.Base(definition), filepath.Ext(definition))
	}
	if name == "" || strings.ContainsAny(name, "\\/\x00\r\n") {
		return "", "", errors.New("a valid SCM service name was not supplied")
	}
	if marker != "" && (!filepath.IsAbs(marker) || strings.ContainsAny(marker, "\x00\r\n")) {
		return "", "", errors.New("the marker path must be absolute and free of control characters")
	}
	return name, marker, nil
}
