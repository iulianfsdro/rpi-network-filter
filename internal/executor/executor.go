package executor

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type Executor struct {
	DryRun  bool
	Timeout time.Duration
}

func New(dryRun bool) *Executor {
	return &Executor{
		DryRun:  dryRun,
		Timeout: 30 * time.Second,
	}
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func (e *Executor) Run(name string, args ...string) (Result, error) {
	cmdStr := name + " " + strings.Join(args, " ")

	if e.DryRun {
		log.Printf("[DRY-RUN] %s", cmdStr)
		return Result{}, nil
	}

	log.Printf("[EXEC] %s", cmdStr)

	ctx, cancel := context.WithTimeout(context.Background(), e.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		return result, fmt.Errorf("exec %s: %w (stderr: %s)", cmdStr, err, stderr.String())
	}

	return result, nil
}

func (e *Executor) RunShell(script string) (Result, error) {
	return e.Run("sh", "-c", script)
}
