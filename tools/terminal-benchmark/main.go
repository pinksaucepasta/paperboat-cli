// Command terminal-benchmark measures a controlled terminal echo session.
// It records timing and process metadata only; terminal contents are discarded.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hinshun/vt10x"
)

type config struct {
	samples       int
	warmup        int
	probeTimeout  time.Duration
	probeAttempts int
	readyTimeout  time.Duration
	readyInterval time.Duration
	startupDelay  time.Duration
	loadWarmup    time.Duration
	interval      time.Duration
	loadCommand   string
	mode          string
	scenario      string
	rttMS         int
	lossPercent   float64
	networkDevice string
}

type result struct {
	Schema            string  `json:"schema"`
	Mode              string  `json:"mode"`
	Scenario          string  `json:"scenario"`
	RTTMS             int     `json:"rtt_ms"`
	LossPercent       float64 `json:"loss_percent"`
	Samples           int     `json:"samples"`
	P50MS             float64 `json:"echo_p50_ms"`
	P95MS             float64 `json:"echo_p95_ms"`
	P99MS             float64 `json:"echo_p99_ms"`
	MeanMS            float64 `json:"echo_mean_ms"`
	MinMS             float64 `json:"echo_min_ms"`
	MaxMS             float64 `json:"echo_max_ms"`
	ElapsedMS         int64   `json:"elapsed_ms"`
	UserCPUMS         int64   `json:"user_cpu_ms"`
	SystemCPUMS       int64   `json:"system_cpu_ms"`
	MaxRSSBytes       int64   `json:"max_rss_bytes,omitempty"`
	WireReceiveBytes  int64   `json:"wire_receive_bytes,omitempty"`
	WireTransmitBytes int64   `json:"wire_transmit_bytes,omitempty"`
	ProbeAttempts     int     `json:"probe_attempts"`
	ProbeTimeouts     int     `json:"probe_timeouts"`
	WarmupAttempts    int     `json:"warmup_attempts"`
	WarmupTimeouts    int     `json:"warmup_timeouts"`
	ReadinessAttempts int     `json:"readiness_attempts"`
	OutputIntervals   int64   `json:"output_interval_samples"`
	OutputP50MS       float64 `json:"output_interval_p50_ms,omitempty"`
	OutputP95MS       float64 `json:"output_interval_p95_ms,omitempty"`
	OutputP99MS       float64 `json:"output_interval_p99_ms,omitempty"`
	OutputMeanMS      float64 `json:"output_interval_mean_ms,omitempty"`
}

type networkCounters struct{ receive, transmit int64 }

const maxOutputIntervalSamples = 1 << 16

type outputIntervals struct {
	mu      sync.Mutex
	last    time.Time
	values  [maxOutputIntervalSamples]time.Duration
	samples int
	count   int64
	total   time.Duration
}

func (o *outputIntervals) observe(at time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.last.IsZero() {
		interval := at.Sub(o.last)
		if interval >= 0 {
			o.count++
			o.total += interval
			if o.samples < len(o.values) {
				o.values[o.samples] = interval
				o.samples++
			}
		}
	}
	o.last = at
}

func (o *outputIntervals) summarize() (count int64, p50, p95, p99, mean float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.count == 0 {
		return 0, 0, 0, 0, 0
	}
	values := append([]time.Duration(nil), o.values[:o.samples]...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return o.count, milliseconds(percentile(values, 50)), milliseconds(percentile(values, 95)), milliseconds(percentile(values, 99)), milliseconds(o.total / time.Duration(o.count))
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "terminal benchmark:", err)
		os.Exit(1)
	}
}

func run(parent context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("terminal-benchmark", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfg := config{}
	flags.IntVar(&cfg.samples, "samples", 100, "recorded echo probes")
	flags.IntVar(&cfg.warmup, "warmup", 10, "unrecorded echo probes")
	flags.DurationVar(&cfg.probeTimeout, "probe-timeout", 10*time.Second, "timeout per echo probe")
	flags.IntVar(&cfg.probeAttempts, "probe-attempts", 5, "maximum fresh attempts per echo probe")
	flags.DurationVar(&cfg.readyTimeout, "ready-timeout", time.Minute, "maximum time to wait for a responsive shell")
	flags.DurationVar(&cfg.readyInterval, "ready-interval", time.Second, "interval between shell readiness probes")
	flags.DurationVar(&cfg.startupDelay, "startup-delay", 2*time.Second, "delay before the first probe")
	flags.StringVar(&cfg.loadCommand, "load-command", "", "shell command to start after readiness; never recorded")
	flags.DurationVar(&cfg.loadWarmup, "load-warmup", 500*time.Millisecond, "delay between starting load and probing")
	flags.DurationVar(&cfg.interval, "interval", 20*time.Millisecond, "delay between probes")
	flags.StringVar(&cfg.mode, "mode", "unknown", "transport label")
	flags.StringVar(&cfg.scenario, "scenario", "idle", "load scenario label")
	flags.IntVar(&cfg.rttMS, "rtt-ms", 0, "configured RTT label")
	flags.Float64Var(&cfg.lossPercent, "loss-percent", 0, "configured loss percentage label")
	flags.StringVar(&cfg.networkDevice, "network-device", "", "Linux interface for aggregate wire-byte counters")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command := flags.Args()
	if cfg.samples < 1 || cfg.warmup < 0 || cfg.samples+cfg.warmup > 1<<16 || cfg.probeTimeout <= 0 || cfg.probeAttempts < 1 || cfg.probeAttempts > 16 || cfg.readyTimeout <= 0 || cfg.readyInterval <= 0 || cfg.startupDelay < 0 || cfg.loadWarmup < 0 || cfg.interval < 0 || strings.ContainsAny(cfg.loadCommand, "\r\n") || len(command) == 0 {
		return errors.New("invalid arguments; provide a command after --")
	}
	if !validLabel(cfg.mode) || !validLabel(cfg.scenario) || cfg.rttMS < 0 || cfg.lossPercent < 0 || cfg.lossPercent > 100 {
		return errors.New("invalid benchmark labels")
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	remoteOutput, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = stderr
	before, _ := readNetworkCounters(cfg.networkDevice)
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return err
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()
	defer func() {
		if processDone == nil {
			return
		}
		cancel()
		_ = stdin.Close()
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-processDone
		}
	}()

	chunks := make(chan []byte, 16)
	readDone := make(chan error, 1)
	outputTiming := &outputIntervals{}
	go readChunks(remoteOutput, chunks, readDone, outputTiming)
	var maxRSS atomic.Int64
	stopRSS := make(chan struct{})
	defer close(stopRSS)
	go monitorRSS(cmd.Process.Pid, &maxRSS, stopRSS)

	matcher := newStreamMatcher(chunks, readDone)
	runPrefix, err := randomRunPrefix(rand.Reader)
	if err != nil {
		return fmt.Errorf("create probe prefix: %w", err)
	}
	if cfg.startupDelay > 0 {
		timer := time.NewTimer(cfg.startupDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	readinessAttempts, err := waitUntilReady(ctx, stdin, matcher, runPrefix, cfg.readyTimeout, cfg.readyInterval)
	if err != nil {
		cancel()
		return err
	}
	if cfg.loadCommand != "" {
		if _, err := io.WriteString(stdin, cfg.loadCommand+"\n"); err != nil {
			cancel()
			return fmt.Errorf("start terminal load: %w", err)
		}
		if err := waitDuration(ctx, cfg.loadWarmup); err != nil {
			cancel()
			return err
		}
	}
	latencies := make([]time.Duration, 0, cfg.samples)
	probeAttempts := 0
	probeTimeouts := 0
	warmupAttempts := 0
	warmupTimeouts := 0
	for index := 0; index < cfg.warmup+cfg.samples; index++ {
		latency, attempts, err := runProbe(ctx, stdin, matcher, runPrefix, index, cfg.probeAttempts, cfg.probeTimeout)
		if err != nil {
			cancel()
			return err
		}
		if index >= cfg.warmup {
			latencies = append(latencies, latency)
			probeAttempts += attempts
			probeTimeouts += attempts - 1
		} else {
			warmupAttempts += attempts
			warmupTimeouts += attempts - 1
		}
		if cfg.interval > 0 {
			//paperboat:allow-source-policy sleep owner=benchmarking reason=operator-configured-probe-pacing
			time.Sleep(cfg.interval)
		}
	}
	_ = stdin.Close()
	select {
	case <-processDone:
	case <-time.After(500 * time.Millisecond):
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-processDone
		}
	}
	processDone = nil
	after, _ := readNetworkCounters(cfg.networkDevice)

	measurement := summarize(cfg, latencies)
	measurement.ElapsedMS = time.Since(started).Milliseconds()
	measurement.MaxRSSBytes = maxRSS.Load()
	if cmd.ProcessState != nil {
		measurement.UserCPUMS = cmd.ProcessState.UserTime().Milliseconds()
		measurement.SystemCPUMS = cmd.ProcessState.SystemTime().Milliseconds()
	}
	measurement.WireReceiveBytes = nonnegativeDelta(after.receive, before.receive)
	measurement.WireTransmitBytes = nonnegativeDelta(after.transmit, before.transmit)
	measurement.ProbeAttempts = probeAttempts
	measurement.ProbeTimeouts = probeTimeouts
	measurement.WarmupAttempts = warmupAttempts
	measurement.WarmupTimeouts = warmupTimeouts
	measurement.ReadinessAttempts = readinessAttempts
	measurement.OutputIntervals, measurement.OutputP50MS, measurement.OutputP95MS, measurement.OutputP99MS, measurement.OutputMeanMS = outputTiming.summarize()
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(measurement)
}

func waitDuration(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func runProbe(ctx context.Context, writer io.Writer, matcher *streamMatcher, runPrefix string, index, maxAttempts int, timeout time.Duration) (time.Duration, int, error) {
	var lastErr error
	value := fmt.Sprintf("%s%04X", runPrefix, index)
	marker := "PB" + value + "Q"
	started := time.Now()
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if _, err := io.WriteString(writer, shellEcho("PB"+value+"Q")); err != nil {
			return 0, attempt + 1, fmt.Errorf("write probe %d attempt %d: %w", index, attempt+1, err)
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		lastErr = matcher.wait(probeCtx, marker)
		cancel()
		if lastErr == nil {
			return time.Since(started), attempt + 1, nil
		}
		if !errors.Is(lastErr, context.DeadlineExceeded) {
			return 0, attempt + 1, fmt.Errorf("wait for probe %d attempt %d: %w", index, attempt+1, lastErr)
		}
	}
	return 0, maxAttempts, fmt.Errorf("wait for probe %d after %d fresh attempts: %w", index, maxAttempts, lastErr)
}

func waitUntilReady(ctx context.Context, writer io.Writer, matcher *streamMatcher, runPrefix string, timeout, interval time.Duration) (int, error) {
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	marker := "PBR" + runPrefix + "Q"
	if _, err := io.WriteString(writer, shellEcho("PBR"+runPrefix+"Q")); err != nil {
		return 1, fmt.Errorf("write readiness probe: %w", err)
	}
	for {
		attemptCtx, attemptCancel := context.WithTimeout(readyCtx, interval)
		err := matcher.wait(attemptCtx, marker)
		attemptCancel()
		if err == nil {
			return 1, nil
		}
		if readyCtx.Err() != nil {
			return 1, fmt.Errorf("wait for responsive shell: %w", readyCtx.Err())
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return 1, fmt.Errorf("wait for responsive shell: %w", err)
		}
	}
}

func shellEcho(value string) string {
	if runtime.GOOS == "windows" {
		return "echo " + value + "\r\n"
	}
	return "printf '" + value + "\\n'\n"
}

func randomRunPrefix(reader io.Reader) (string, error) {
	var value [4]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(value[:])), nil
}

type streamMatcher struct {
	chunks      <-chan []byte
	done        <-chan error
	screen      vt10x.Terminal
	chunkCount  uint64
	byteCount   uint64
	checkpoints uint64
}

func newStreamMatcher(chunks <-chan []byte, done <-chan error) *streamMatcher {
	return &streamMatcher{
		chunks: chunks,
		done:   done,
		screen: vt10x.New(vt10x.WithSize(80, 24)),
	}
}

func (m *streamMatcher) wait(ctx context.Context, marker string) error {
	for {
		if m.screenContains(marker) {
			return nil
		}
		select {
		case chunk, ok := <-m.chunks:
			if !ok {
				err := <-m.done
				if err == nil {
					err = io.EOF
				}
				return err
			}
			matched, err := m.consume(chunk, marker)
			if err != nil {
				return err
			}
			if matched {
				return nil
			}
		case err := <-m.done:
			if err == nil {
				err = io.EOF
			}
			return err
		case <-ctx.Done():
			// Account for output that arrived before the deadline but lost the
			// select race. Do not wait for any output arriving after the deadline.
			for queued := len(m.chunks); queued > 0; queued-- {
				chunk, ok := <-m.chunks
				if !ok {
					break
				}
				matched, err := m.consume(chunk, marker)
				if err != nil {
					return err
				}
				if matched {
					return nil
				}
			}
			return m.timeoutError(ctx.Err(), marker)
		}
	}
}

func (m *streamMatcher) consume(chunk []byte, marker string) (bool, error) {
	m.chunkCount++
	m.byteCount += uint64(len(chunk))
	last := marker[len(marker)-1]
	for len(chunk) > 0 {
		end := len(chunk)
		if index := bytes.IndexByte(chunk, last); index >= 0 {
			end = index + 1
		}
		if _, err := m.screen.Write(chunk[:end]); err != nil {
			return false, fmt.Errorf("render terminal output: %w", err)
		}
		chunk = chunk[end:]
		m.checkpoints++
		if m.screenContains(marker) {
			return true, nil
		}
	}
	return false, nil
}

func (m *streamMatcher) timeoutError(cause error, marker string) error {
	cursor := m.screen.Cursor()
	return fmt.Errorf("%w (rendered chunks=%d bytes=%d checkpoints=%d cursor=%d,%d marker_prefix=%d)", cause, m.chunkCount, m.byteCount, m.checkpoints, cursor.X, cursor.Y, m.longestMarkerPrefix(marker))
}

func (m *streamMatcher) longestMarkerPrefix(marker string) int {
	rendered := m.renderedScreen()
	for size := len(marker); size > 0; size-- {
		if strings.Contains(rendered, marker[:size]) {
			return size
		}
	}
	return 0
}

func (m *streamMatcher) screenContains(marker string) bool {
	return strings.Contains(m.renderedScreen(), marker)
}

func (m *streamMatcher) renderedScreen() string {
	cols, rows := m.screen.Size()
	m.screen.Lock()
	defer m.screen.Unlock()
	var screen strings.Builder
	screen.Grow(cols * rows)
	for row := 0; row < rows; row++ {
		for col := 0; col < cols; col++ {
			char := m.screen.Cell(col, row).Char
			if char == 0 {
				char = ' '
			}
			screen.WriteRune(char)
		}
	}
	return screen.String()
}

func readChunks(reader io.Reader, chunks chan<- []byte, done chan<- error, intervals *outputIntervals) {
	defer close(chunks)
	buffer := make([]byte, 32<<10)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			intervals.observe(time.Now())
			chunks <- append([]byte(nil), buffer[:n]...)
		}
		if err != nil {
			done <- err
			return
		}
	}
}

func summarize(cfg config, values []time.Duration) result {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var total time.Duration
	for _, value := range sorted {
		total += value
	}
	return result{Schema: "paperboat.terminal-benchmark/v1", Mode: cfg.mode, Scenario: cfg.scenario, RTTMS: cfg.rttMS, LossPercent: cfg.lossPercent, Samples: len(sorted), P50MS: milliseconds(percentile(sorted, 50)), P95MS: milliseconds(percentile(sorted, 95)), P99MS: milliseconds(percentile(sorted, 99)), MeanMS: milliseconds(total / time.Duration(len(sorted))), MinMS: milliseconds(sorted[0]), MaxMS: milliseconds(sorted[len(sorted)-1])}
}

func percentile(sorted []time.Duration, percent int) time.Duration {
	index := (percent*len(sorted) + 99) / 100
	if index < 1 {
		index = 1
	}
	return sorted[index-1]
}

func milliseconds(value time.Duration) float64 { return float64(value) / float64(time.Millisecond) }

func validLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if r != '_' && r != '-' && r != '.' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func readNetworkCounters(device string) (networkCounters, error) {
	if device == "" || filepath.Base(device) != device {
		return networkCounters{}, errors.New("invalid network device")
	}
	read := func(name string) (int64, error) {
		value, err := os.ReadFile(filepath.Join("/sys/class/net", device, "statistics", name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
	}
	receive, err := read("rx_bytes")
	if err != nil {
		return networkCounters{}, err
	}
	transmit, err := read("tx_bytes")
	return networkCounters{receive: receive, transmit: transmit}, err
}

func monitorRSS(pid int, maximum *atomic.Int64, stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) == 3 && fields[0] == "VmRSS:" {
					kilobytes, _ := strconv.ParseInt(fields[1], 10, 64)
					updateMaximum(maximum, kilobytes*1024)
					break
				}
			}
			_ = file.Close()
		}
		select {
		case <-ticker.C:
		case <-stop:
			return
		}
	}
}

func updateMaximum(value *atomic.Int64, candidate int64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func nonnegativeDelta(after, before int64) int64 {
	if after < before {
		return 0
	}
	return after - before
}
