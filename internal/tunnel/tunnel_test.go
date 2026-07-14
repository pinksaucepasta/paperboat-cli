package tunnel

import (
	"testing"
	"time"
)

func TestReadBufferedChunksWithWaitCoalescesStaggeredOutput(t *testing.T) {
	out := make(chan []byte, 2)
	out <- []byte("first")
	go func() {
		time.Sleep(time.Millisecond)
		out <- []byte("second")
	}()

	buf := make([]byte, 32)
	var pending []byte
	n, err := readBufferedChunksWithWait(buf, &pending, out, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "firstsecond" {
		t.Fatalf("output = %q", got)
	}
}
