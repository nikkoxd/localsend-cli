package main

import (
	"fmt"
	"io"
	"log"
	"sync"
)

// LogLevel represents the verbosity of logging.
type LogLevel int

const (
	LevelError LogLevel = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

func (l LogLevel) String() string {
	switch l {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// Logger provides leveled logging to a writer.
type Logger struct {
	level  LogLevel
	output *log.Logger
	mu     sync.Mutex
}

// NewLogger creates a logger that writes to w.
func NewLogger(w io.Writer, level LogLevel) *Logger {
	return &Logger{
		level:  level,
		output: log.New(w, "", 0),
	}
}

func (l *Logger) logf(level LogLevel, format string, args ...any) {
	if level > l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	prefix := fmt.Sprintf("[%s] ", level)
	l.output.Printf(prefix+format, args...)
}

// Errorf logs an error message.
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

// Warnf logs a warning message.
func (l *Logger) Warnf(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Infof logs an info message.
func (l *Logger) Infof(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Debugf logs a debug message.
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }

