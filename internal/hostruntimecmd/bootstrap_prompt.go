package hostruntimecmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

func promptBootstrapValue(reader *bufio.Reader, output io.Writer, label string, value *string) error {
	*value = strings.TrimSpace(*value)
	if *value != "" {
		return nil
	}
	fmt.Fprintf(output, "%s: ", label)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	*value = strings.TrimSpace(line)
	if *value == "" {
		return fmt.Errorf("%s is required", strings.ToLower(label))
	}
	return nil
}
