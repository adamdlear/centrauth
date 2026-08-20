package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/adamdlear/centrauth/internal"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	cfg, err := internal.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	app := internal.NewApp(cfg)

	if err := app.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
