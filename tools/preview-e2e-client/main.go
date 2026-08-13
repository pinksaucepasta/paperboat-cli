package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/coder/websocket"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: preview-e2e-client <websocket-url> <payload>")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, os.Args[1], nil)
	if err == nil {
		defer connection.CloseNow()
		err = connection.Write(ctx, websocket.MessageText, []byte(os.Args[2]))
	}
	var response []byte
	if err == nil {
		_, response, err = connection.Read(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(string(response))
}
