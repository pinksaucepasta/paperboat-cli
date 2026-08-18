//go:build windows

package pty

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ErrInvalidCommand    = errors.New("invalid PTY command")
	ErrInvalidCWD        = errors.New("invalid PTY cwd")
	ErrInvalidDimensions = errors.New("invalid PTY dimensions")
	ErrInvalidSignal     = errors.New("invalid PTY signal")
)

type Dimensions struct {
	Columns uint16 `json:"columns"`
	Rows    uint16 `json:"rows"`
}
type Command struct {
	Path       string
	Args       []string
	Env        []string
	CWD        string
	Dimensions Dimensions
}
type ExitResult struct {
	Code     int       `json:"code"`
	Signal   string    `json:"signal,omitempty"`
	ExitedAt time.Time `json:"exited_at"`
}
type Signal string

const (
	Interrupt Signal = "SIGINT"
	Terminate Signal = "SIGTERM"
	Hangup    Signal = "SIGHUP"
	Kill      Signal = "SIGKILL"
)

type Adapter struct{ root string }

func NewAdapter(root string) (*Adapter, error) {
	resolved, err := resolveDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("root: %w", ErrInvalidCWD)
	}
	return &Adapter{root: resolved}, nil
}

func (a *Adapter) Start(command Command) (*Process, error) {
	path, err := ValidateProcessPolicy(command.Path, command.Args, command.Env)
	if err != nil {
		return nil, err
	}
	cwd, err := resolveDirectory(command.CWD)
	if err != nil || !within(a.root, cwd) {
		return nil, ErrInvalidCWD
	}
	if !validDimensions(command.Dimensions) {
		return nil, ErrInvalidCommand
	}
	inputRead, inputWrite, err := anonymousPipe()
	if err != nil {
		return nil, fmt.Errorf("create ConPTY input pipe: %w", err)
	}
	outputRead, outputWrite, err := anonymousPipe()
	if err != nil {
		closeHandles(inputRead, inputWrite)
		return nil, fmt.Errorf("create ConPTY output pipe: %w", err)
	}
	console := windows.Handle(0)
	coord := windows.Coord{X: int16(command.Dimensions.Columns), Y: int16(command.Dimensions.Rows)}
	if err := windows.CreatePseudoConsole(coord, inputRead, outputWrite, 0, &console); err != nil {
		closeHandles(inputRead, inputWrite, outputRead, outputWrite)
		return nil, fmt.Errorf("create ConPTY: %w", err)
	}
	// ConPTY owns the console-side pipe handles after creation. The host keeps
	// only the write side of input and read side of output.
	windows.Close(inputRead)
	windows.Close(outputWrite)

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("create PTY job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("configure PTY job: %w", err)
	}

	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("create process attributes: %w", err)
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(&console), unsafe.Sizeof(console)); err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("configure process ConPTY: %w", err)
	}
	commandLine, err := commandLine(path, command.Args)
	if err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, err
	}
	workingDirectory, err := windows.UTF16PtrFromString(cwd)
	if err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, err
	}
	environment, err := environmentBlock(command.Env)
	if err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, err
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.ProcThreadAttributeList = attributes.List()
	var processInfo windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(nil, &commandLine[0], nil, nil, false, flags, environment, workingDirectory, &startup.StartupInfo, &processInfo); err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("start ConPTY process: %w", err)
	}
	windows.Close(processInfo.Thread)
	if err := windows.AssignProcessToJobObject(job, processInfo.Process); err != nil {
		_ = windows.TerminateProcess(processInfo.Process, 1)
		windows.Close(processInfo.Process)
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("assign process to PTY job: %w", err)
	}
	process := &Process{
		input:   os.NewFile(uintptr(inputWrite), "paperboat-conpty-input"),
		output:  os.NewFile(uintptr(outputRead), "paperboat-conpty-output"),
		console: console, process: processInfo.Process, job: job, done: make(chan struct{}),
	}
	go process.wait()
	return process, nil
}

type Process struct {
	input     *os.File
	output    *os.File
	console   windows.Handle
	process   windows.Handle
	job       windows.Handle
	done      chan struct{}
	mu        sync.RWMutex
	result    ExitResult
	waitErr   error
	closeOnce sync.Once
}

func (p *Process) Read(buffer []byte) (int, error) { return p.output.Read(buffer) }
func (p *Process) Write(data []byte) (int, error)  { return p.input.Write(data) }
func (p *Process) Resize(dimensions Dimensions) error {
	if !validDimensions(dimensions) {
		return ErrInvalidDimensions
	}
	return windows.ResizePseudoConsole(p.console, windows.Coord{X: int16(dimensions.Columns), Y: int16(dimensions.Rows)})
}
func (p *Process) Signal(signal Signal) error {
	if signal != Interrupt && signal != Terminate && signal != Hangup && signal != Kill {
		return ErrInvalidSignal
	}
	p.mu.RLock()
	process := p.process
	p.mu.RUnlock()
	if process == 0 {
		return os.ErrProcessDone
	}
	code := uint32(1)
	if signal == Kill {
		code = 137
	}
	if err := windows.TerminateProcess(process, code); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
func (p *Process) Wait(ctx context.Context) (ExitResult, error) {
	select {
	case <-p.done:
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.result, p.waitErr
	case <-ctx.Done():
		return ExitResult{}, ctx.Err()
	}
}
func (p *Process) CloseIO() error {
	var err error
	p.closeOnce.Do(func() {
		err = errors.Join(p.input.Close(), p.output.Close())
		windows.ClosePseudoConsole(p.console)
		windows.Close(p.process)
		windows.Close(p.job)
	})
	return err
}
func (p *Process) Terminate(ctx context.Context, grace time.Duration) (ExitResult, error) {
	if grace < 0 {
		return ExitResult{}, ErrInvalidCommand
	}
	select {
	case <-p.done:
		result, err := p.Wait(context.Background())
		_ = p.CloseIO()
		return result, err
	default:
	}
	if err := p.Signal(Terminate); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return ExitResult{}, err
	}
	graceCtx, cancel := context.WithTimeout(ctx, grace)
	result, err := p.Wait(graceCtx)
	cancel()
	if err == nil {
		_ = p.CloseIO()
		return result, nil
	}
	if ctx.Err() != nil {
		return ExitResult{}, ctx.Err()
	}
	if err := p.Signal(Kill); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return ExitResult{}, err
	}
	result, err = p.Wait(ctx)
	_ = p.CloseIO()
	return result, err
}
func (p *Process) wait() {
	_, waitErr := windows.WaitForSingleObject(p.process, windows.INFINITE)
	var code uint32
	if waitErr == nil {
		waitErr = windows.GetExitCodeProcess(p.process, &code)
	}
	result := ExitResult{Code: int(code), ExitedAt: time.Now().UTC()}
	p.mu.Lock()
	p.result, p.waitErr = result, waitErr
	p.mu.Unlock()
	close(p.done)
}

func anonymousPipe() (windows.Handle, windows.Handle, error) {
	var read, write windows.Handle
	if err := windows.CreatePipe(&read, &write, nil, 0); err != nil {
		return 0, 0, err
	}
	if err := windows.SetHandleInformation(read, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.Close(read)
		windows.Close(write)
		return 0, 0, err
	}
	if err := windows.SetHandleInformation(write, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.Close(read)
		windows.Close(write)
		return 0, 0, err
	}
	return read, write, nil
}
func closeHandles(values ...windows.Handle) {
	for _, value := range values {
		if value != 0 {
			windows.Close(value)
		}
	}
}
func commandLine(path string, args []string) ([]uint16, error) {
	line := syscall.EscapeArg(path)
	for _, argument := range args {
		if strings.ContainsRune(argument, '\x00') {
			return nil, ErrInvalidCommand
		}
		line += " " + syscall.EscapeArg(argument)
	}
	return windows.UTF16FromString(line)
}
func environmentBlock(environment []string) (*uint16, error) {
	if len(environment) == 0 {
		return nil, nil
	}
	copyEnvironment := append([]string(nil), environment...)
	// CreateProcess requires a sorted, double-NUL-terminated UTF-16 block.
	sortStrings(copyEnvironment)
	return windows.UTF16PtrFromString(strings.Join(copyEnvironment, "\x00") + "\x00")
}
func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && strings.ToUpper(values[cursor]) < strings.ToUpper(values[cursor-1]); cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}
func validDimensions(dimensions Dimensions) bool {
	return dimensions.Columns >= 1 && dimensions.Columns <= 1000 && dimensions.Rows >= 1 && dimensions.Rows <= 1000
}
func validEnvironment(environment []string) bool {
	if len(environment) > 128 {
		return false
	}
	seen := make(map[string]bool, len(environment))
	total := 0
	for _, entry := range environment {
		total += len(entry)
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || len(entry) > 4096 || total > 64<<10 || strings.ContainsAny(key, "\x00\r\n") || strings.ContainsRune(value, '\x00') || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
func validArguments(arguments []string) bool {
	if len(arguments) > 64 {
		return false
	}
	total := 0
	for _, argument := range arguments {
		total += len(argument)
		if len(argument) > 4096 || total > 64<<10 || strings.ContainsRune(argument, '\x00') {
			return false
		}
	}
	return true
}
func ValidateProcessPolicy(path string, arguments, environment []string) (string, error) {
	resolved, err := validateExecutable(path)
	if err != nil || !validArguments(arguments) || !validEnvironment(environment) {
		return "", ErrInvalidCommand
	}
	return resolved, nil
}
func validateExecutable(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrInvalidCommand
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", ErrInvalidCommand
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrInvalidCommand
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(resolved))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", ErrInvalidCommand
	}
	return resolved, nil
}
func resolveDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrInvalidCWD
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", ErrInvalidCWD
	}
	return filepath.Clean(resolved), nil
}
func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
