package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

func main() {
	handler := http.NewServeMux()
	handler.HandleFunc("/http", func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "preview-http-ok\n") })
	handler.HandleFunc("/sse", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := writer.(http.Flusher)
		for _, value := range []string{"one", "two"} {
			fmt.Fprintf(writer, "data: %s\n\n", value)
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})
	handler.HandleFunc("/stream", func(writer http.ResponseWriter, request *http.Request) { _, _ = io.Copy(writer, request.Body) })
	handler.HandleFunc("/ws", func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		kind, value, err := connection.Read(request.Context())
		if err == nil {
			_ = connection.Write(request.Context(), kind, append([]byte("echo:"), value...))
		}
	})
	if err := http.ListenAndServe("127.0.0.1:38142", handler); err != nil {
		panic(err)
	}
}
