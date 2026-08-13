package relaynoise

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStreamCarrierPreservesConcurrentRecordSequence(t *testing.T) {
	initiatorSession, responderSession := sessions(t)
	left, right := net.Pipe()
	sender, err := NewStreamCarrier(left)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewStreamCarrier(right)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const count = 32
	received := make(chan string, count)
	receiveErr := make(chan error, 1)
	go func() {
		for range count {
			record, err := receiver.ReceiveRecord(ctx)
			if err != nil {
				receiveErr <- err
				return
			}
			payload, _, err := responderSession.Open(record)
			if err != nil {
				receiveErr <- err
				return
			}
			received <- string(payload)
		}
		receiveErr <- nil
	}()
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if err := sender.Send(ctx, initiatorSession, []byte(fmt.Sprintf("record-%02d", index)), false); err != nil {
				t.Error(err)
			}
		}(index)
	}
	wait.Wait()
	if err := <-receiveErr; err != nil {
		t.Fatal(err)
	}
	close(received)
	seen := make(map[string]bool, count)
	for payload := range received {
		seen[payload] = true
	}
	if len(seen) != count {
		t.Fatalf("received=%d", len(seen))
	}
}

func TestStreamCarrierCancellationInterruptsRead(t *testing.T) {
	left, right := net.Pipe()
	carrier, _ := NewStreamCarrier(left)
	defer carrier.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := carrier.ReceiveRecord(ctx)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled read remained blocked")
	}
}

func TestStreamCarrierRejectsMalformedLengthBeforeAllocation(t *testing.T) {
	left, right := net.Pipe()
	carrier, _ := NewStreamCarrier(left)
	defer carrier.Close()
	defer right.Close()
	header := make([]byte, headerLength)
	header[0] = recordVersion
	binary.BigEndian.PutUint16(header[26:28], authenticationBytes-1)
	go func() { _, _ = right.Write(header) }()
	if _, err := carrier.ReceiveRecord(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}
