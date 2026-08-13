package filetransfer

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type readWriteSeeker interface {
	io.Reader
	io.Writer
	io.Seeker
}

// EncryptedChunkReader exposes the carrier-independent ciphertext representation
// for one prepared source. It never returns plaintext and is safe to retry from
// a committed chunk ordinal because nonce derivation is ordinal-based.
type EncryptedChunkReader struct {
	source   Source
	material transfercrypto.KeyMaterial
	context  transfercrypto.ChunkContext
	reader   io.ReaderAt
}

func (r *EncryptedChunkReader) Close() error {
	if r == nil {
		return nil
	}
	r.material.Destroy()
	r.reader = nil
	return nil
}

// EncryptedChunkWriter authenticates and stages one ordered file. Complete must
// succeed before the caller atomically publishes the staging file.
type EncryptedChunkWriter struct {
	writer    io.Writer
	material  transfercrypto.KeyMaterial
	context   transfercrypto.ChunkContext
	expected  transfercrypto.ManifestFile
	hash      hash.Hash
	next      uint64
	written   uint64
	poisoned  bool
	completed bool
}

func (w *EncryptedChunkWriter) Close() error {
	if w == nil {
		return nil
	}
	w.material.Destroy()
	w.writer = nil
	w.poisoned = true
	return nil
}

func NewEncryptedChunkWriter(writer io.Writer, material transfercrypto.KeyMaterial, context transfercrypto.ChunkContext, expected transfercrypto.ManifestFile) (*EncryptedChunkWriter, error) {
	if writer == nil || transfercrypto.ValidateManifestFile(expected) != nil || transfercrypto.ValidateChunkContext(material, context) != nil || context.FileOrdinal != expected.FileOrdinal || context.ChunkOrdinal != 0 || context.Final {
		return nil, errors.New("invalid encrypted transfer destination")
	}
	return &EncryptedChunkWriter{writer: writer, material: material, context: context, expected: expected, hash: sha256.New()}, nil
}

func NewResumingEncryptedChunkWriter(file readWriteSeeker, material transfercrypto.KeyMaterial, context transfercrypto.ChunkContext, expected transfercrypto.ManifestFile) (*EncryptedChunkWriter, uint64, error) {
	writer, err := NewEncryptedChunkWriter(file, material, context, expected)
	if err != nil {
		return nil, 0, err
	}
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil || size < 0 || uint64(size) > expected.Size || uint64(size) < expected.Size && size%transfercrypto.ChunkSize != 0 {
		writer.Close()
		return nil, 0, errors.New("invalid encrypted transfer resume offset")
	}
	committed := uint64(size) / transfercrypto.ChunkSize
	if uint64(size) == expected.Size {
		committed = expected.ChunkCount
	}
	if committed > expected.ChunkCount {
		writer.Close()
		return nil, 0, errors.New("invalid encrypted transfer resume ordinal")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writer.Close()
		return nil, 0, err
	}
	if copied, err := io.CopyN(writer.hash, file, size); err != nil || copied != size {
		writer.Close()
		return nil, 0, errors.Join(err, io.ErrUnexpectedEOF)
	}
	if _, err := file.Seek(size, io.SeekStart); err != nil {
		writer.Close()
		return nil, 0, err
	}
	writer.next = committed
	writer.written = uint64(size)
	return writer, committed, nil
}

func (w *EncryptedChunkWriter) WriteChunk(ciphertext []byte) error {
	if w == nil || w.poisoned || w.completed || w.next >= w.expected.ChunkCount {
		return errors.New("encrypted transfer destination is unavailable")
	}
	context := w.context
	context.ChunkOrdinal = w.next
	context.Final = w.next+1 == w.expected.ChunkCount
	plaintext, err := transfercrypto.DecryptChunk(w.material, context, ciphertext)
	if err != nil {
		w.poisoned = true
		return err
	}
	defer clear(plaintext)
	want := uint64(transfercrypto.ChunkSize)
	if context.Final {
		want = w.expected.Size - w.written
	}
	if uint64(len(plaintext)) != want {
		w.poisoned = true
		return errors.New("encrypted transfer chunk length mismatch")
	}
	written, err := w.writer.Write(plaintext)
	if err != nil || written != len(plaintext) {
		w.poisoned = true
		return errors.Join(err, io.ErrShortWrite)
	}
	if _, err := w.hash.Write(plaintext); err != nil {
		w.poisoned = true
		return err
	}
	w.written += uint64(written)
	w.next++
	return nil
}

func (w *EncryptedChunkWriter) Complete() error {
	if w == nil || w.poisoned || w.completed || w.next != w.expected.ChunkCount || w.written != w.expected.Size {
		return errors.New("encrypted transfer is incomplete")
	}
	digest := w.hash.Sum(nil)
	if subtle.ConstantTimeCompare(digest, w.expected.PlaintextSHA256[:]) != 1 {
		w.poisoned = true
		return errors.New("encrypted transfer plaintext digest mismatch")
	}
	w.completed = true
	return nil
}

func NewEncryptedChunkReader(source Source, material transfercrypto.KeyMaterial, context transfercrypto.ChunkContext) (*EncryptedChunkReader, error) {
	if source.Reader == nil || source.Size < 0 || transfercrypto.ValidateChunkContext(material, context) != nil || context.ChunkOrdinal != 0 || context.Final {
		return nil, errors.New("invalid encrypted transfer source")
	}
	reader, ok := source.Reader.(io.ReaderAt)
	if !ok {
		return nil, errors.New("encrypted transfer source must support positioned reads")
	}
	return &EncryptedChunkReader{source: source, material: material, context: context, reader: reader}, nil
}

func (r *EncryptedChunkReader) ReadChunk(ordinal uint64) ([]byte, bool, error) {
	if r == nil || r.reader == nil || ordinal > ^uint64(0)/transfercrypto.ChunkSize {
		return nil, false, errors.New("invalid encrypted chunk ordinal")
	}
	offset := ordinal * transfercrypto.ChunkSize
	if offset >= uint64(r.source.Size) && !(r.source.Size == 0 && ordinal == 0) {
		return nil, false, io.EOF
	}
	length := transfercrypto.ChunkSize
	remaining := uint64(r.source.Size) - offset
	if remaining < uint64(length) {
		length = int(remaining)
	}
	plaintext := make([]byte, length)
	defer clear(plaintext)
	if length > 0 {
		read, err := r.reader.ReadAt(plaintext, int64(offset))
		if err != nil && !(err == io.EOF && read == length) {
			return nil, false, err
		}
		if read != length {
			return nil, false, io.ErrUnexpectedEOF
		}
	}
	context := r.context
	context.ChunkOrdinal = ordinal
	context.Final = offset+uint64(length) == uint64(r.source.Size)
	ciphertext, err := transfercrypto.EncryptChunk(r.material, context, plaintext)
	if err != nil {
		return nil, false, err
	}
	return ciphertext, context.Final, nil
}
