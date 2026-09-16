//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"testing"
	"time"
)

func TestRunBudgetStartsOnceAtFirstPreflightRead(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	parentDeadline, _ := parent.Deadline()
	prepared := filesystemFixtureContext(t, parent)
	if _, _, started := prepared.budget.snapshot(); started {
		t.Fatal("lexical preparation started execution budget")
	}
	before := time.Now()
	files, err := OpenLocationFiles(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	start, deadline, started := prepared.budget.snapshot()
	if !started || start.Before(before) || !deadline.Equal(parentDeadline) || files.budget != prepared.budget {
		t.Fatal("first read did not bind parent-clipped budget", start, deadline, parentDeadline)
	}
	_, path, digest := executableFixture(t)
	executable, err := OpenExecutable(context.Background(), prepared, path, digest, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	secondStart, secondDeadline, _ := prepared.budget.snapshot()
	if !secondStart.Equal(start) || !secondDeadline.Equal(deadline) || executable.budget != prepared.budget {
		t.Fatal("later preflight read reset or detached budget")
	}
}

func TestRunBudgetUsesLockedExecutionLimitWithoutParentDeadline(t *testing.T) {
	prepared := filesystemFixture(t)
	files, err := OpenLocationFiles(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	start, deadline, started := prepared.budget.snapshot()
	if !started || deadline.Sub(start) != runExecutionLimit || runExecutionLimit != 1800*time.Second || caseExecutionLimit != 120*time.Second {
		t.Fatal("locked execution limits changed", start, deadline)
	}
}
