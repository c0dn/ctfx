package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/c0dn/ctfx/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st, _ := os.Stdout.Stat()
	app := &cli.App{Version: version, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		IsTTY: st != nil && st.Mode()&os.ModeCharDevice != 0}
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
