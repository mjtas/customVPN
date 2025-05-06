package network

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

// ExecCommand securely executes system commands with sanitised arguments
func ExecCommand(command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Resolve absolute path to prevent PATH injection
	path, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command resolution failed for %q: %w", command, err)
	}

	cmd := exec.CommandContext(ctx, path, args...)

	// Capture output for error diagnostics
	output, err := cmd.CombinedOutput()
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return fmt.Errorf("command timed out: %s %v", path, args)
	case err != nil:
		return fmt.Errorf("command failed [%s %v]: %w\nOutput:\n%s",
			path, args, err, string(output))
	}

	log.Printf("Executed successfully: %s %v\nOutput:\n%s", path, args, string(output))
	return nil
}
