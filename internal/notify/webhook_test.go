package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookHMACDeliveryAndShutdown(t *testing.T) {
	secret := "vesper-hmac-secret-99"
	type received struct {
		sig  string
		body []byte
	}
	gotCh := make(chan received, 1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotCh <- received{
			sig:  r.Header.Get("X-Vesper-Signature"),
			body: raw,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n := NewNotifier("https://auth.starryheavens.uk", ts.URL, secret)
	n.Notify("auth.login_rate_limited", "warning", "starry", "203.0.113.10", "password", "lockout triggered")
	n.Close()

	rec := <-gotCh
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rec.body)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if rec.sig != wantSig {
		t.Fatalf("signature mismatch: got %q want %q", rec.sig, wantSig)
	}

	var ev Event
	if err := json.Unmarshal(rec.body, &ev); err != nil {
		t.Fatalf("unmarshal webhook body: %v", err)
	}
	if ev.EventType != "auth.login_rate_limited" || ev.Actor != "starry" || ev.Text == "" {
		t.Fatalf("unexpected webhook event: %+v", ev)
	}
}
