package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/cli"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/server"
	"github.com/YN1753/vesper-auth/internal/store"
)

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	handled, err := cli.Run(os.Args[1:], cli.BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
	}, os.Stdin, os.Stdout, os.Stderr)
	if handled {
		if err != nil {
			slog.Error("cli command failed", "err", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		slog.Error("database open error", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Warn("database close error", "err", err)
		}
	}()

	if err := bootstrapAdminIfConfigured(cfg, st); err != nil {
		slog.Error("admin bootstrap error", "err", err)
		os.Exit(1)
	}

	maintCtx, stopMaint := context.WithCancel(context.Background())
	defer stopMaint()
	st.StartMaintenanceLoop(maintCtx, time.Hour, cfg.AuditRetentionDays)

	srv, err := server.New(cfg, st)
	if err != nil {
		slog.Error("server init error", "err", err)
		os.Exit(1)
	}
	srv.SetVersion(version)
	defer srv.Close()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("vesper-auth listening",
			"addr", cfg.ListenAddr,
			"issuer", cfg.Issuer,
			"db", cfg.DBPath,
			"version", version,
		)
		errCh <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received shutdown signal", "signal", sig.String())
		stopMaint()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Warn("graceful shutdown error", "err", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server error", "err", err)
			os.Exit(1)
		}
	}
}

func bootstrapAdminIfConfigured(cfg *config.Config, st *store.Store) error {
	has, err := st.HasAdmin()
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	if cfg.AdminPassword == "" {
		slog.Info("no admin user found; open /setup in browser to initialize", "setup_url", cfg.Issuer+"/setup")
		return nil
	}

	hash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	user, err := st.CreateAdmin(cfg.AdminUsername, cfg.AdminEmail, cfg.AdminUsername, hash)
	if err != nil {
		return err
	}
	_ = st.RecordAudit("auth.bootstrap", user.Username, "127.0.0.1", "vesper-auth-init", user.ID, "admin bootstrapped from environment", "success")
	slog.Info("bootstrapped administrator", "username", user.Username, "email", user.Email)
	return nil
}
