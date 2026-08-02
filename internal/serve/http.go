package serve

import (
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
)

type HandlerConfig struct {
	Source Source
	SPA    bool
}

func NewHandler(config HandlerConfig) (http.Handler, error) {
	if err := config.Source.Revalidate(); err != nil {
		return nil, err
	}
	if config.Source.Kind == SourceFile && config.SPA {
		return nil, ErrInvalidSource
	}
	if config.Source.Kind == SourceFile {
		return safetyHeaders(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			serveSingleFile(writer, request, config.Source)
		})), nil
	}
	root, err := os.OpenRoot(config.Source.Path)
	if err != nil {
		return nil, err
	}
	return safetyHeaders(&directoryHandler{source: config.Source, root: root, spa: config.SPA}), nil
}

func serveSingleFile(writer http.ResponseWriter, request *http.Request, source Source) {
	if request.URL.Path != "/" || request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.NotFound(writer, request)
		return
	}
	if err := source.Revalidate(); err != nil {
		http.Error(writer, "source unavailable", http.StatusGone)
		return
	}
	file, err := os.Open(source.Path)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(source.info, info) {
		http.Error(writer, "source unavailable", http.StatusGone)
		return
	}
	setContentHeaders(writer.Header(), file, source.Path)
	http.ServeContent(writer, request, info.Name(), info.ModTime(), file)
}

type directoryHandler struct {
	source Source
	root   *os.Root
	spa    bool
}

func (h *directoryHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.NotFound(writer, request)
		return
	}
	if h.source.Revalidate() != nil {
		http.Error(writer, "source unavailable", http.StatusGone)
		return
	}
	relative, ok := requestPath(request.URL.Path)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	if h.servePath(writer, request, relative) {
		return
	}
	if h.spa && navigationRequest(request, relative) && h.servePath(writer, request, "index.html") {
		return
	}
	http.NotFound(writer, request)
}

func (h *directoryHandler) servePath(writer http.ResponseWriter, request *http.Request, relative string) bool {
	file, err := h.root.Open(relative)
	if err != nil {
		return false
	}
	info, err := file.Stat()
	if err == nil && info.IsDir() {
		file.Close()
		index := path.Join(relative, "index.html")
		if relative == "." {
			index = "index.html"
		}
		file, err = h.root.Open(index)
		if err != nil {
			return false
		}
		info, err = file.Stat()
	}
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return false
	}
	defer file.Close()
	setContentHeaders(writer.Header(), file, info.Name())
	http.ServeContent(writer, request, info.Name(), info.ModTime(), file)
	return true
}

func requestPath(value string) (string, bool) {
	rawParts := strings.Split(strings.TrimPrefix(value, "/"), "/")
	for _, part := range rawParts {
		if part == "." || part == ".." || strings.HasPrefix(part, ".") || strings.ContainsRune(part, '\x00') || strings.Contains(part, `\`) {
			return "", false
		}
	}
	cleaned := path.Clean("/" + value)
	parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") || strings.ContainsRune(part, '\x00') || strings.Contains(part, `\`) {
			return "", false
		}
	}
	if len(parts) == 1 && parts[0] == "" {
		return ".", true
	}
	return strings.Join(parts, "/"), true
}

func navigationRequest(request *http.Request, relative string) bool {
	if path.Ext(relative) != "" {
		return false
	}
	accept := request.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func setContentHeaders(header http.Header, file *os.File, name string) {
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		buffer := make([]byte, 512)
		read, _ := file.Read(buffer)
		contentType = http.DetectContentType(buffer[:read])
		_, _ = file.Seek(0, io.SeekStart)
	}
	header.Set("Content-Type", contentType)
	if !inlineContentType(contentType) {
		header.Set("Content-Disposition", "attachment")
	}
}

func inlineContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "text/") || strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") || mediaType == "application/pdf"
}

type safetyHandler struct{ next http.Handler }

func (h safetyHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	header := writer.Header()
	header.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	h.next.ServeHTTP(writer, request)
}

func (h safetyHandler) Close() error {
	if closer, ok := h.next.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func (h *directoryHandler) Close() error { return h.root.Close() }

func safetyHeaders(next http.Handler) http.Handler {
	return safetyHandler{next: next}
}
