//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/creack/pty"
)

type config struct {
	runs, samples int
	startup       time.Duration
	timeout       time.Duration
	interval      time.Duration
	pb, target    string
	sshHost       string
	sshKey        string
	sshPort       int
}

type result struct {
	Transport string  `json:"transport"`
	Run       int     `json:"run"`
	Samples   int     `json:"samples"`
	P50MS     float64 `json:"input_p50_ms"`
	P95MS     float64 `json:"input_p95_ms"`
	P99MS     float64 `json:"input_p99_ms"`
	MaxMS     float64 `json:"input_max_ms"`
	Over200MS int     `json:"responses_over_200_ms"`
	Over500MS int     `json:"responses_over_500_ms"`
}

type aggregate struct {
	Summary        bool    `json:"summary"`
	Transport      string  `json:"transport"`
	Runs           int     `json:"runs"`
	Samples        int     `json:"samples"`
	MedianP50MS    float64 `json:"median_input_p50_ms"`
	MedianP95MS    float64 `json:"median_input_p95_ms"`
	MedianP99MS    float64 `json:"median_input_p99_ms"`
	MedianMaxMS    float64 `json:"median_input_max_ms"`
	WorstMS        float64 `json:"worst_input_ms"`
	TotalOver200MS int     `json:"total_responses_over_200_ms"`
	TotalOver500MS int     `json:"total_responses_over_500_ms"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "terminal input benchmark:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("terminal-input-benchmark", flag.ContinueOnError)
	cfg := config{}
	flags.IntVar(&cfg.runs, "runs", 10, "runs per transport")
	flags.IntVar(&cfg.samples, "samples", 50, "raw key responses per run")
	flags.DurationVar(&cfg.startup, "pb-startup", 3*time.Second, "time allowed for pb to attach")
	flags.DurationVar(&cfg.timeout, "timeout", 3*time.Second, "timeout per key response")
	flags.DurationVar(&cfg.interval, "interval", 20*time.Millisecond, "delay between keys")
	flags.StringVar(&cfg.pb, "pb", "pb", "pb executable")
	flags.StringVar(&cfg.target, "target", "hn", "Paperboat environment")
	flags.StringVar(&cfg.sshHost, "ssh-host", "root@157.180.74.88", "SSH destination")
	flags.StringVar(&cfg.sshKey, "ssh-key", "", "SSH private key")
	flags.IntVar(&cfg.sshPort, "ssh-port", 22, "SSH port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if cfg.runs < 1 || cfg.runs > 20 || cfg.samples < 5 || cfg.samples > 1000 || cfg.startup < time.Second || cfg.timeout <= 0 || cfg.interval < 0 || cfg.sshPort < 1 || cfg.sshPort > 65535 {
		return errors.New("invalid benchmark configuration")
	}

	encoder := json.NewEncoder(output)
	all := make(map[string][]result)
	transports := []string{"ssh", "pb_quic", "pb_wss"}
	for runIndex := 1; runIndex <= cfg.runs; runIndex++ {
		offset := (runIndex - 1) % len(transports)
		order := append(append([]string{}, transports[offset:]...), transports[:offset]...)
		for _, transport := range order {
			value, err := measure(ctx, cfg, transport, runIndex)
			if err != nil {
				return fmt.Errorf("%s run %d: %w", transport, runIndex, err)
			}
			if err := encoder.Encode(value); err != nil {
				return err
			}
			all[transport] = append(all[transport], value)
		}
	}
	for _, transport := range transports {
		if err := encoder.Encode(summarizeRuns(transport, all[transport])); err != nil {
			return err
		}
	}
	return nil
}

func measure(parent context.Context, cfg config, transport string, runIndex int) (result, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	remote := `exec env TERM=xterm-256color python3 -u -c "import os,tty;tty.setraw(0);[(lambda b:os.write(1,b'PBIN'+b))(os.read(0,1)) for _ in iter(int,1)]"`
	var command *exec.Cmd
	pbSession := ""
	if transport == "ssh" {
		args := []string{"-tt", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", fmt.Sprint(cfg.sshPort)}
		if cfg.sshKey != "" {
			args = append(args, "-i", cfg.sshKey)
		}
		args = append(args, cfg.sshHost, remote)
		command = exec.CommandContext(ctx, "ssh", args...)
	} else {
		pbSession = fmt.Sprintf("input-bench-%s-%d-%d", transport[3:], time.Now().UnixNano(), runIndex)
		defer deletePBSession(cfg.pb, cfg.target, pbSession)
		command = exec.CommandContext(ctx, cfg.pb, "connect", cfg.target, "new", "--path", paperboatPath(transport), "--name", pbSession, "--status-bar", "off")
	}
	terminal, err := pty.StartWithSize(command, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		return result{}, err
	}
	defer terminal.Close()
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	chunks := make(chan []byte, 256)
	go readChunks(terminal, chunks)
	matcher := streamMatcher{chunks: chunks}
	if pbSession != "" {
		if err := matcher.waitAny(cfg.startup, []byte("# "), []byte("$ ")); err != nil {
			return result{}, fmt.Errorf("remote shell did not become ready: %w", err)
		}
		if _, err := io.WriteString(terminal, remote+"\n"); err != nil {
			return result{}, err
		}
	}
	if err := waitResponder(terminal, &matcher, cfg.startup); err != nil {
		return result{}, fmt.Errorf("raw responder did not become ready: %w (output %q)", err, matcher.pending)
	}

	values := make([]time.Duration, 0, cfg.samples)
	for index := 0; index < cfg.samples; index++ {
		key := byte('a' + index%26)
		started := time.Now()
		if _, err := terminal.Write([]byte{key}); err != nil {
			return result{}, err
		}
		if err := matcher.wait([]byte{'P', 'B', 'I', 'N', key}, cfg.timeout); err != nil {
			return result{}, err
		}
		values = append(values, time.Since(started))
		if err := sleep(ctx, cfg.interval); err != nil {
			return result{}, err
		}
	}
	_, _ = terminal.Write([]byte{3})
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
		cancel()
		<-processDone
	}
	return summarize(transport, runIndex, values), nil
}

func paperboatPath(transport string) string {
	switch transport {
	case "pb_quic":
		return "q"
	case "pb_wss":
		return "w"
	default:
		return ""
	}
}

func (m *streamMatcher) waitAny(timeout time.Duration, markers ...[]byte) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		for _, marker := range markers {
			if index := bytes.Index(m.pending, marker); index >= 0 {
				m.pending = m.pending[index+len(marker):]
				return nil
			}
		}
		select {
		case chunk, ok := <-m.chunks:
			if !ok {
				return io.EOF
			}
			m.pending = append(m.pending, chunk...)
		case <-timer.C:
			return errors.New("response timeout")
		}
	}
}

func waitResponder(terminal io.Writer, matcher *streamMatcher, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := terminal.Write([]byte{'W'}); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		attempt := 500 * time.Millisecond
		if remaining < attempt {
			attempt = remaining
		}
		if err := matcher.wait([]byte("PBINW"), attempt); err == nil {
			return nil
		} else if errors.Is(err, io.EOF) {
			return err
		}
	}
	return errors.New("response timeout")
}

type streamMatcher struct {
	chunks  <-chan []byte
	pending []byte
}

func (m *streamMatcher) wait(marker []byte, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if index := bytes.Index(m.pending, marker); index >= 0 {
			m.pending = m.pending[index+len(marker):]
			return nil
		}
		if len(m.pending) > 4096 {
			m.pending = append([]byte(nil), m.pending[len(m.pending)-4096:]...)
		}
		select {
		case chunk, ok := <-m.chunks:
			if !ok {
				return io.EOF
			}
			m.pending = append(m.pending, chunk...)
		case <-timer.C:
			return errors.New("response timeout")
		}
	}
}

func readChunks(reader io.Reader, output chan<- []byte) {
	defer close(output)
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			output <- append([]byte(nil), buffer[:n]...)
		}
		if err != nil {
			return
		}
	}
}

func summarize(transport string, runIndex int, values []time.Duration) result {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	value := result{Transport: transport, Run: runIndex, Samples: len(values)}
	value.P50MS = milliseconds(percentile(values, 50))
	value.P95MS = milliseconds(percentile(values, 95))
	value.P99MS = milliseconds(percentile(values, 99))
	value.MaxMS = milliseconds(values[len(values)-1])
	for _, duration := range values {
		if duration > 200*time.Millisecond {
			value.Over200MS++
		}
		if duration > 500*time.Millisecond {
			value.Over500MS++
		}
	}
	return value
}

func summarizeRuns(transport string, values []result) aggregate {
	summary := aggregate{Summary: true, Transport: transport, Runs: len(values)}
	p50, p95, p99, maximums := []float64{}, []float64{}, []float64{}, []float64{}
	for _, value := range values {
		summary.Samples += value.Samples
		summary.TotalOver200MS += value.Over200MS
		summary.TotalOver500MS += value.Over500MS
		p50, p95, p99, maximums = append(p50, value.P50MS), append(p95, value.P95MS), append(p99, value.P99MS), append(maximums, value.MaxMS)
		if value.MaxMS > summary.WorstMS {
			summary.WorstMS = value.MaxMS
		}
	}
	summary.MedianP50MS, summary.MedianP95MS = median(p50), median(p95)
	summary.MedianP99MS, summary.MedianMaxMS = median(p99), median(maximums)
	return summary
}

func deletePBSession(pb, target, session string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, pb, "session", "delete", target, session, "--yes").Run()
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func percentile(values []time.Duration, percent int) time.Duration {
	index := (len(values)*percent + 99) / 100
	if index < 1 {
		index = 1
	}
	return values[index-1]
}

func median(values []float64) float64 {
	sort.Float64s(values)
	if len(values) == 0 {
		return 0
	}
	return values[(len(values)-1)/2]
}

func milliseconds(value time.Duration) float64 { return float64(value) / float64(time.Millisecond) }
