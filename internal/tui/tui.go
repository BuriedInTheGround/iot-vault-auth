package tui

import (
	"log"
	"os"
)

var l = log.New(os.Stderr, "", 0)

var ProgramName string

func Infof(format string, v ...any) {
	l.Printf(ProgramName+": info: "+format, v...)
}

func Warningf(format string, v ...any) {
	l.Printf(ProgramName+": warning: "+format, v...)
}

func Errorf(format string, v ...any) {
	l.Fatalf(ProgramName+": error: "+format, v...)
}
