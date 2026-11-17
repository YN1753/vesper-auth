package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/oidc"
	"github.com/YN1753/vesper-auth/internal/store"
)

// BuildInfo holds compile-time version metadata injected via -ldflags.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

// Run executes a CLI subcommand when args is non-empty (excluding "serve").
// Returns handled=false if the caller should proceed with starting the HTTP server.
func Run(args []string, info BuildInfo, stdin io.Reader, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 || args[0] == "serve" {
		return false, nil
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "vesper-auth %s (commit=%s built=%s go=%s)\n",
			nonEmpty(info.Version, "dev"),
			nonEmpty(info.Commit, "none"),
			nonEmpty(info.BuildTime, "unknown"),
			runtime.Version(),
		)
		return true, nil

	case "help", "--help", "-h":
		printUsage(stdout)
		return true, nil

	case "backup":
		return true, runBackup(args[1:], stdout)

	case "admin":
		return true, runAdmin(args[1:], stdin, stdout, stderr)

	default:
		printUsage(stderr)
		return true, fmt.Errorf("unknown command %q", args[0])
	}
}

func runBackup(args []string, stdout io.Writer) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: vesper-auth backup <destination-file>")
	}
	dest := args[0]

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := st.BackupTo(ctx, dest); err != nil {
		return err
	}
	fi, err := os.Stat(dest)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "backup verified: %s (%d bytes)\n", dest, fi.Size())
	return nil
}

func runAdmin(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: vesper-auth admin <reset-password|list-passkeys|delete-passkey|rotate-key>")
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "reset-password":
		fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
		fs.SetOutput(stderr)
		pwdFlag := fs.String("password", "", "new master password (min 10 chars)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pwd := strings.TrimSpace(*pwdFlag)
		if pwd == "" {
			pwd = strings.TrimSpace(os.Getenv("AUTH_NEW_PASSWORD"))
		}
		if pwd == "" && stdin != nil {
			fmt.Fprint(stderr, "Enter new master password (min 10 chars): ")
			sc := bufio.NewScanner(stdin)
			if sc.Scan() {
				pwd = strings.TrimSpace(sc.Text())
			}
		}
		if len(pwd) < 10 {
			return errors.New("new password must be at least 10 characters")
		}

		hash, err := auth.HashPassword(pwd)
		if err != nil {
			return err
		}

		has, err := st.HasAdmin()
		if err != nil {
			return err
		}
		if !has {
			user, err := st.CreateAdmin(cfg.AdminUsername, cfg.AdminEmail, cfg.AdminUsername, hash)
			if err != nil {
				return err
			}
			_ = st.RecordAudit("cli.admin_create", user.Username, "127.0.0.1", "vesper-auth-cli", user.ID, "created initial admin via CLI", "success")
			fmt.Fprintf(stdout, "initialized admin %q (%s)\n", user.Username, user.Email)
			return nil
		}

		user, err := st.GetAdmin()
		if err != nil {
			return err
		}
		if err := st.UpdateAdminPassword(user.ID, hash); err != nil {
			return err
		}
		sesCount, _ := st.DeleteAllSessions(user.ID)
		_ = st.RevokeAllUserTokens(user.ID)
		_ = st.RecordAudit("cli.password_reset", user.Username, "127.0.0.1", "vesper-auth-cli", user.ID, fmt.Sprintf("revoked_sessions=%d", sesCount), "success")
		fmt.Fprintf(stdout, "password updated for %q; revoked %d active session(s) and all OAuth tokens\n", user.Username, sesCount)
		return nil

	case "list-passkeys":
		user, err := st.GetAdmin()
		if err != nil {
			return errors.New("no administrator initialized")
		}
		pks, err := st.ListPasskeys(user.ID)
		if err != nil {
			return err
		}
		if len(pks) == 0 {
			fmt.Fprintln(stdout, "no passkeys registered")
			return nil
		}
		for _, pk := range pks {
			fmt.Fprintf(stdout, "%s\tname=%q\tsign_count=%d\tcreated=%s\tlast_used=%s\n",
				pk.ID,
				pk.Name,
				pk.SignCount,
				time.Unix(pk.CreatedAt, 0).UTC().Format(time.RFC3339),
				time.Unix(pk.LastUsedAt, 0).UTC().Format(time.RFC3339),
			)
		}
		return nil

	case "delete-passkey":
		if len(args) != 2 {
			return errors.New("usage: vesper-auth admin delete-passkey <pk_id|--all>")
		}
		user, err := st.GetAdmin()
		if err != nil {
			return errors.New("no administrator initialized")
		}
		target := strings.TrimSpace(args[1])
		if target == "--all" {
			n, err := st.DeleteAllPasskeys(user.ID)
			if err != nil {
				return err
			}
			_ = st.RecordAudit("cli.passkey_clear", user.Username, "127.0.0.1", "vesper-auth-cli", "all", fmt.Sprintf("deleted=%d", n), "success")
			fmt.Fprintf(stdout, "deleted %d passkey(s)\n", n)
			return nil
		}
		name, err := st.DeletePasskey(user.ID, target)
		if err != nil {
			return err
		}
		_ = st.RecordAudit("cli.passkey_delete", user.Username, "127.0.0.1", "vesper-auth-cli", name, "id="+target, "success")
		fmt.Fprintf(stdout, "deleted passkey %s (%s)\n", target, name)
		return nil

	case "rotate-key":
		ks, err := oidc.LoadOrCreateKeySet(st)
		if err != nil {
			return err
		}
		rk, err := ks.Rotate(st, cfg.KeyRetainCount)
		if err != nil {
			return err
		}
		_ = st.RecordAudit("cli.key_rotate", "cli", "127.0.0.1", "vesper-auth-cli", rk.KID, "rotated RS256 signing key via CLI", "success")
		fmt.Fprintf(stdout, "rotated RS256 signing key; new active kid=%s\n", rk.KID)
		return nil

	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vesper-auth [serve]                              Start HTTP SSO server
  vesper-auth version                              Print build version
  vesper-auth backup <dest-file>                   Create atomic online SQLite backup
  vesper-auth admin reset-password --password <p>  Reset admin master password and revoke sessions
  vesper-auth admin list-passkeys                  List bound WebAuthn Passkeys
  vesper-auth admin delete-passkey <id|--all>      Unbind a Passkey or all Passkeys
  vesper-auth admin rotate-key                     Rotate RS256 OIDC signing keypair
`)
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
