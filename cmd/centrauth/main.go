package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/adamdlear/centrauth/internal"
	"github.com/adamdlear/centrauth/internal/db"
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

	database, err := db.New(cfg.DBConfig)
	if err != nil {
		log.Fatal(err)
	}

	app := internal.NewApp(cfg, database)

	if err := app.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
