package utils

import (
	"context"
	"io"
	"os/exec"
)

func Execute(path string, reader io.Reader, writer io.Writer, args ...string) error {
	cmd := exec.Command(path, args...)
	cmd.Stdin = reader
	cmd.Stderr = writer
	cmd.Stdout = writer
	return cmd.Run()
}

func ExecuteWithContext(ctx context.Context, path string, reader io.Reader, writer io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = reader
	cmd.Stdout = writer
	cmd.Stderr = writer
	return cmd.Run()
}
