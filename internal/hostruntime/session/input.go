package session

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	helperconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
)

type InputStatus string

const (
	InputAccepted  InputStatus = "accepted"
	InputDuplicate InputStatus = "duplicate"
	InputRejected  InputStatus = "rejected"
	InputUncertain InputStatus = "uncertain"
)

var (
	ErrInvalidInput     = errors.New("invalid input identity")
	ErrInputConflict    = errors.New("input id reused with different content")
	ErrInputSequence    = errors.New("input sequence is not contiguous")
	ErrInputUncertain   = errors.New("previous input delivery is uncertain")
	ErrStaleGeneration  = errors.New("stale process generation")
	ErrInputUnknown     = errors.New("input decision not found")
	ErrInputJournalFull = errors.New("input decision journal is full")
)

type StaleGenerationError struct{ CurrentGeneration uint64 }

func (e *StaleGenerationError) Error() string {
	return fmt.Sprintf("current generation %d: %v", e.CurrentGeneration, ErrStaleGeneration)
}
func (e *StaleGenerationError) Unwrap() error { return ErrStaleGeneration }

type InputKey struct {
	ClientID     string
	AttachmentID string
	Generation   uint64
	// InputSequence is monotonically increasing for one client, attachment,
	// and process generation. It is the only identity used by the live
	// terminal protocol. InputID is retained solely so old on-disk fixtures can
	// be read while development migrations are in flight; new callers must set
	// InputSequence.
	InputSequence uint64
	InputID       string
}

type InputDecision struct {
	Status        InputStatus `json:"status"`
	InputSequence uint64      `json:"input_sequence"`
	BytesWritten  int         `json:"bytes_written"`
	WriteError    string      `json:"write_error,omitempty"`
	hash          [sha256.Size]byte
}

type InputWriter interface{ Write([]byte) (int, error) }

type InputJournal struct {
	mu        sync.Mutex
	current   uint64
	max       int
	decisions map[InputKey]InputDecision
	last      map[inputCursor]uint64
}

type inputCursor struct {
	clientID     string
	attachmentID string
	generation   uint64
}

func NewInputJournal(generation uint64) *InputJournal {
	return NewBoundedInputJournal(generation, helperconfig.DefaultResources.MaxInputDecisions)
}

func NewBoundedInputJournal(generation uint64, max int) *InputJournal {
	return &InputJournal{current: generation, max: max, decisions: make(map[InputKey]InputDecision), last: make(map[inputCursor]uint64)}
}

func (j *InputJournal) SetGeneration(generation uint64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.current = generation
}

func (j *InputJournal) Write(key InputKey, data []byte, writer InputWriter) (InputDecision, error) {
	key, legacy := normalizeInputKey(key)
	if key.ClientID == "" || key.AttachmentID == "" || key.Generation == 0 || (key.InputSequence == 0 && key.InputID == "") || writer == nil {
		return InputDecision{}, ErrInvalidInput
	}
	hash := sha256.Sum256(data)
	j.mu.Lock()
	if previous, ok := j.decisions[key]; ok {
		j.mu.Unlock()
		if previous.hash != hash {
			return InputDecision{}, ErrInputConflict
		}
		if legacy && previous.Status == InputAccepted {
			previous.Status = InputDuplicate
		}
		return publicDecision(previous), nil
	}
	if len(j.decisions) >= j.max {
		j.mu.Unlock()
		return InputDecision{}, ErrInputJournalFull
	}
	if key.Generation != j.current {
		current := j.current
		j.mu.Unlock()
		return InputDecision{}, &StaleGenerationError{CurrentGeneration: current}
	}
	if key.InputSequence != 0 {
		cursor := inputCursor{clientID: key.ClientID, attachmentID: key.AttachmentID, generation: key.Generation}
		if last := j.last[cursor]; last != 0 {
			if previous, ok := j.decisions[InputKey{ClientID: key.ClientID, AttachmentID: key.AttachmentID, Generation: key.Generation, InputSequence: last}]; ok && previous.Status == InputUncertain {
				j.mu.Unlock()
				return InputDecision{}, ErrInputUncertain
			}
			if key.InputSequence != last+1 {
				j.mu.Unlock()
				return InputDecision{}, ErrInputSequence
			}
		}
	}
	// Reserve the identity before touching the PTY. A process crash, worker
	// replacement, or short write therefore leaves an explicit uncertain
	// decision that a reconnect can query instead of guessing whether bytes
	// reached the workload.
	decision := InputDecision{Status: InputUncertain, InputSequence: key.InputSequence, hash: hash}
	j.decisions[key] = decision
	if key.InputSequence != 0 {
		cursor := inputCursor{clientID: key.ClientID, attachmentID: key.AttachmentID, generation: key.Generation}
		j.last[cursor] = key.InputSequence
	}
	j.mu.Unlock()
	n, err := writer.Write(data)
	decision.BytesWritten = n
	switch {
	case n == len(data):
		decision.Status = InputAccepted
	case n == 0:
		decision.Status = InputRejected
	default:
		decision.Status = InputUncertain
	}
	if err != nil {
		decision.WriteError = "pty_write_failed"
		if n > 0 && n < len(data) {
			decision.Status = InputUncertain
		}
	}
	if key.InputSequence != 0 {
		decision.InputSequence = key.InputSequence
	}
	j.mu.Lock()
	if current, exists := j.decisions[key]; exists && current.hash == hash {
		j.decisions[key] = decision
	}
	j.mu.Unlock()
	return publicDecision(decision), nil
}

func (j *InputJournal) Query(key InputKey) (InputDecision, error) {
	key, _ = normalizeInputKey(key)
	j.mu.Lock()
	defer j.mu.Unlock()
	decision, ok := j.decisions[key]
	if !ok {
		return InputDecision{}, ErrInputUnknown
	}
	return publicDecision(decision), nil
}

func (j *InputJournal) Admit(key InputKey) error {
	key, _ = normalizeInputKey(key)
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.decisions[key]; exists {
		return nil
	}
	if len(j.decisions) >= j.max {
		return ErrInputJournalFull
	}
	if key.InputSequence != 0 {
		cursor := inputCursor{clientID: key.ClientID, attachmentID: key.AttachmentID, generation: key.Generation}
		if last := j.last[cursor]; last != 0 {
			if previous, ok := j.decisions[InputKey{ClientID: key.ClientID, AttachmentID: key.AttachmentID, Generation: key.Generation, InputSequence: last}]; ok && previous.Status == InputUncertain {
				return ErrInputUncertain
			}
			if key.InputSequence != last+1 {
				return ErrInputSequence
			}
		}
	}
	return nil
}

func (j *InputJournal) Restore(key InputKey, hash []byte, status InputStatus, bytesWritten int, errorCode string) error {
	key, _ = normalizeInputKey(key)
	if len(hash) != sha256.Size || key.ClientID == "" || key.AttachmentID == "" || (key.InputSequence == 0 && key.InputID == "") || key.Generation == 0 {
		return ErrInvalidInput
	}
	if status != InputAccepted && status != InputRejected && status != InputUncertain {
		return ErrInvalidInput
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash)
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.decisions[key]; exists {
		return ErrInputConflict
	}
	if len(j.decisions) >= j.max {
		return ErrInputJournalFull
	}
	j.decisions[key] = InputDecision{Status: status, InputSequence: key.InputSequence, BytesWritten: bytesWritten, WriteError: errorCode, hash: digest}
	if key.InputSequence != 0 {
		cursor := inputCursor{clientID: key.ClientID, attachmentID: key.AttachmentID, generation: key.Generation}
		if key.InputSequence > j.last[cursor] {
			j.last[cursor] = key.InputSequence
		}
	}
	return nil
}

// LastSequence returns the highest durable sequence for one terminal input
// identity. A reconnect uses it to resume at the next sequence without
// replaying an input whose delivery result is unknown.
func (j *InputJournal) LastSequence(clientID, attachmentID string, generation uint64) uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.last[inputCursor{clientID: clientID, attachmentID: attachmentID, generation: generation}]
}

func normalizeInputKey(key InputKey) (InputKey, bool) {
	if key.InputSequence != 0 {
		key.InputID = ""
		return key, false
	}
	return key, true
}

func publicDecision(decision InputDecision) InputDecision {
	decision.hash = [sha256.Size]byte{}
	return decision
}
