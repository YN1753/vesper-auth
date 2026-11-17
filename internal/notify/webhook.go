package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event represents a security alert emitted to an external webhook such as BotHub.
type Event struct {
	Source    string `json:"source"`
	Issuer    string `json:"issuer"`
	EventType string `json:"event"`
	Severity  string `json:"severity"`
	Actor     string `json:"actor"`
	IP        string `json:"ip"`
	Target    string `json:"target,omitempty"`
	Detail    string `json:"detail"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

// Notifier dispatches security alerts asynchronously without blocking request handlers.
type Notifier struct {
	webhookURL string
	secret     string
	issuer     string
	client     *http.Client
	ch         chan Event
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

// NewNotifier creates a webhook Notifier. If webhookURL is empty, Notify becomes a safe no-op.
func NewNotifier(issuer, webhookURL, secret string) *Notifier {
	n := &Notifier{
		webhookURL: strings.TrimSpace(webhookURL),
		secret:     strings.TrimSpace(secret),
		issuer:     issuer,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	if n.webhookURL != "" {
		n.ch = make(chan Event, 64)
		n.wg.Add(1)
		go n.worker()
	}
	return n
}

// Enabled reports whether a webhook destination is configured.
func (n *Notifier) Enabled() bool {
	return n != nil && n.webhookURL != ""
}

// Notify enqueues a security alert for asynchronous delivery.
func (n *Notifier) Notify(eventType, severity, actor, ip, target, detail string) {
	if !n.Enabled() {
		return
	}
	ev := Event{
		Source:    "vesper-auth",
		Issuer:    n.issuer,
		EventType: eventType,
		Severity:  severity,
		Actor:     actor,
		IP:        ip,
		Target:    target,
		Detail:    detail,
		Text:      fmt.Sprintf("[Vesper Auth] %s (%s) actor=%s ip=%s target=%s detail=%s", eventType, severity, actor, ip, target, detail),
		Timestamp: time.Now().Unix(),
	}
	select {
	case n.ch <- ev:
	default:
		slog.Warn("alert webhook queue full, dropping event", "event", eventType)
	}
}

// Close flushes queued events and stops the background worker.
func (n *Notifier) Close() {
	if !n.Enabled() {
		return
	}
	n.stopOnce.Do(func() {
		close(n.ch)
		n.wg.Wait()
	})
}

func (n *Notifier) worker() {
	defer n.wg.Done()
	for ev := range n.ch {
		n.deliver(ev)
	}
}

func (n *Notifier) deliver(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		slog.Warn("alert webhook build request failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "Vesper-Auth-Webhook/1.0")
	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		mac.Write(body)
		req.Header.Set("X-Vesper-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := n.client.Do(req)
	if err != nil {
		slog.Warn("alert webhook delivery failed", "event", ev.EventType, "err", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("alert webhook returned error status", "event", ev.EventType, "status", resp.StatusCode)
	}
}
