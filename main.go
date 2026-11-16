package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/server"
	"github.com/YN1753/vesper-auth/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("vesper-auth: config error: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("vesper-auth: database open error: %v", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Printf("vesper-auth: database close error: %v", err)
		}
	}()

	if err := bootstrapAdminIfConfigured(cfg, st); err != nil {
		log.Fatalf("vesper-auth: admin bootstrap error: %v", err)
	}

	srv, err := server.New(cfg, st)
	if err != nil {
		log.Fatalf("vesper-auth: server init error: %v", err)
	}

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
		log.Printf("vesper-auth listening on %s (issuer=%s, db=%s)", cfg.ListenAddr, cfg.Issuer, cfg.DBPath)
		errCh <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("vesper-auth received signal %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("vesper-auth graceful shutdown error: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("vesper-auth server error: %v", err)
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
		log.Printf("vesper-auth: no admin user found; open %s/setup in browser to initialize", cfg.Issuer)
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
	log.Printf("vesper-auth: bootstrapped administrator %q (%s)", user.Username, user.Email)
	return nil
}
