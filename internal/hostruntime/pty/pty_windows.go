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
	inputRead, inputWrite, err := anonymousPipe(true)
	if err != nil {
		return nil, fmt.Errorf("create ConPTY input pipe: %w", err)
	}
	outputRead, outputWrite, err := anonymousPipe(false)
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
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE takes the HPCON handle value,
	// represented as a pointer-sized value. Passing &console attaches a pointer
	// to the local variable instead and creates a child that never exchanges
	// input or output with the pseudoconsole.
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(console), unsafe.Sizeof(console)); err != nil {
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
	// Do not set STARTF_USESTDHANDLES here. ConPTY owns the child console
	// streams through PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE; advertising null
	// standard handles makes CreateProcess reject the launch with
	// ERROR_INVALID_HANDLE, which is especially visible when hostd runs as a
	// Windows service without inherited console handles.
	startup.ProcThreadAttributeList = attributes.List()
	var processInfo windows.ProcessInformation
	// CREATE_NEW_PROCESS_GROUP disables Ctrl+C handling for the new process.
	// ConPTY sessions need terminal ETX input to reach the foreground command,
	// so process-tree ownership comes from the Job Object instead.
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(nil, &commandLine[0], nil, nil, false, flags, environment, workingDirectory, &startup.StartupInfo, &processInfo); err != nil {
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("start ConPTY process: %w", err)
	}
	if err := windows.AssignProcessToJobObject(job, processInfo.Process); err != nil {
		_ = windows.TerminateProcess(processInfo.Process, 1)
		windows.Close(processInfo.Process)
		windows.Close(processInfo.Thread)
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("assign process to PTY job: %w", err)
	}
	if _, err := windows.ResumeThread(processInfo.Thread); err != nil {
		_ = windows.TerminateProcess(processInfo.Process, 1)
		windows.Close(processInfo.Process)
		windows.Close(processInfo.Thread)
		windows.Close(job)
		windows.ClosePseudoConsole(console)
		closeHandles(inputWrite, outputRead)
		return nil, fmt.Errorf("resume ConPTY process: %w", err)
	}
	windows.Close(processInfo.Thread)
	process := &Process{
		input:   os.NewFile(uintptr(inputWrite), "paperboat-conpty-input"),
		output:  os.NewFile(uintptr(outputRead), "paperboat-conpty-output"),
		console: console, process: processInfo.Process, processID: processInfo.ProcessId, job: job, done: make(chan struct{}),
	}
	go process.wait()
	return process, nil
}

type Process struct {
	input       *os.File
	output      *os.File
	console     windows.Handle
	process     windows.Handle
	processID   uint32
	job         windows.Handle
	done        chan struct{}
	mu          sync.RWMutex
	result      ExitResult
	waitErr     error
	consoleOnce sync.Once
	closeOnce   sync.Once
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
	if signal == Interrupt {
		// ConPTY translates the terminal ETX byte into the same Ctrl+C input
		// event an interactive console receives. Do not terminate the shell:
		// the foreground command must be interrupted while the session remains
		// usable for subsequent commands.
		if _, err := p.input.Write([]byte{0x03}); err != nil {
			return err
		}
		// Some inbox console applications on Windows 11 do not translate ETX
		// into a control event when hosted below cmd.exe in ConPTY. Give native
		// handling a short opportunity, then terminate only foreground
		// descendants. The shell remains alive and all processes stay bounded by
		// the same Job Object.
		//paperboat:allow-source-policy sleep owner=windows-conpty reason=bounded-native-ctrl-c-grace-before-descendant-fallback
		time.Sleep(100 * time.Millisecond)
		for _, pid := range jobProcessIDs(p.job) {
			if pid == p.processID {
				continue
			}
			handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
			if err != nil {
				continue
			}
			_ = windows.TerminateProcess(handle, 130)
			windows.CloseHandle(handle)
		}
		return nil
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

func jobProcessIDs(job windows.Handle) []uint32 {
	// JOBOBJECT_BASIC_PROCESS_ID_LIST has two DWORD counters followed by a
	// pointer-width process ID array. Cap collection to 256 processes so signal
	// handling remains bounded even under a hostile workload.
	const maximumProcesses = 256
	buffer := make([]byte, 8+maximumProcesses*int(unsafe.Sizeof(uintptr(0))))
	var returned uint32
	if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buffer[0])), uint32(len(buffer)), &returned); err != nil {
		return nil
	}
	assigned := *(*uint32)(unsafe.Pointer(&buffer[4]))
	if assigned > maximumProcesses {
		assigned = maximumProcesses
	}
	result := make([]uint32, 0, assigned)
	offset := 8
	stride := int(unsafe.Sizeof(uintptr(0)))
	for index := uint32(0); index < assigned && offset+stride <= len(buffer); index++ {
		pid := *(*uintptr)(unsafe.Pointer(&buffer[offset]))
		if pid != 0 && pid <= uintptr(^uint32(0)) {
			result = append(result, uint32(pid))
		}
		offset += stride
	}
	return result
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
		p.closeConsole()
		windows.Close(p.process)
		windows.Close(p.job)
	})
	return err
}
func (p *Process) closeConsole() {
	p.consoleOnce.Do(func() { windows.ClosePseudoConsole(p.console) })
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
	// ConPTY does not close its output pipe merely because the attached process
	// exited. Closing the pseudoconsole releases the final VT output and lets the
	// session capture loop observe EOF, after which it can publish exact exit
	// state. Keep this on the waiter goroutine while capture drains output: the
	// Windows API may wait for pending pseudoconsole output to be consumed.
	p.closeConsole()
}

// anonymousPipe creates the pipe pair used by ConPTY. The pseudoconsole API
// expects the console-side endpoint to remain inheritable while the host-side
// endpoint stays private. Clearing inheritance on both ends makes the
// subsequent ConPTY child launch fail from a service process.
func anonymousPipe(inheritRead bool) (windows.Handle, windows.Handle, error) {
	var read, write windows.Handle
	// CreatePseudoConsole requires the console-side endpoint to be inheritable.
	// CreatePipe does not make handles inheritable when its security attributes
	// argument is nil, even though the subsequent child launch uses the
	// pseudoconsole attribute. Keep the host-side endpoint private immediately
	// after creating the pair.
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&read, &write, &security, 0); err != nil {
		return 0, 0, err
	}
	private := read
	if inheritRead {
		private = write
	}
	if err := windows.SetHandleInformation(private, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
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
