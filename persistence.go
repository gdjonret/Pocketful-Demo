package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	persistenceStateKey = "pocketful:demo:state:v1"
	persistenceLockKey  = "pocketful:demo:lock:v1"
)

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == http.StatusOK {
		b.status = status
	}
}
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) flushTo(w http.ResponseWriter) {
	for k, values := range b.header {
		for _, value := range values {
			w.Header().Add(k, value)
		}
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

func persistenceCredentials() (string, string, bool) {
	url := strings.TrimRight(os.Getenv("UPSTASH_REDIS_REST_URL"), "/")
	token := os.Getenv("UPSTASH_REDIS_REST_TOKEN")
	if url == "" {
		url = strings.TrimRight(os.Getenv("KV_REST_API_URL"), "/")
	}
	if token == "" {
		token = os.Getenv("KV_REST_API_TOKEN")
	}
	return url, token, url != "" && token != ""
}

func redisCommand(ctx context.Context, command ...any) (json.RawMessage, error) {
	url, token, ok := persistenceCredentials()
	if !ok {
		return nil, errors.New("persistence is not configured")
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("persistence returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if envelope.Error != "" {
		return nil, errors.New(envelope.Error)
	}
	return envelope.Result, nil
}

func randomLockToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func acquirePersistenceLock(ctx context.Context) (string, error) {
	token := randomLockToken()
	deadline := time.Now().Add(8 * time.Second)
	for {
		result, err := redisCommand(ctx, "SET", persistenceLockKey, token, "NX", "PX", 30000)
		if err != nil {
			return "", err
		}
		var value *string
		if string(result) != "null" {
			var v string
			if json.Unmarshal(result, &v) == nil {
				value = &v
			}
		}
		if value != nil && *value == "OK" {
			return token, nil
		}
		if time.Now().After(deadline) {
			return "", errors.New("timed out waiting for persistence lock")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(80 * time.Millisecond):
		}
	}
}

func releasePersistenceLock(ctx context.Context, token string) {
	script := `if redis.call("get",KEYS[1]) == ARGV[1] then return redis.call("del",KEYS[1]) else return 0 end`
	if _, err := redisCommand(ctx, "EVAL", script, 1, persistenceLockKey, token); err != nil {
		log.Printf("warning: could not release persistence lock: %v", err)
	}
}

func normalizeState(st *State) {
	if st.Users == nil {
		st.Users = map[string]*User{}
	}
	if st.Payments == nil {
		st.Payments = map[string]*Payment{}
	}
	if st.Requests == nil {
		st.Requests = map[string]*Request{}
	}
	if st.PaymentSeq == nil {
		st.PaymentSeq = map[string]int64{}
	}
	if st.RequestSeq == nil {
		st.RequestSeq = map[string]int64{}
	}
	if st.Authorizations == nil {
		st.Authorizations = map[string]*Authorization{}
	}
	if st.AuthorizationSeq == nil {
		st.AuthorizationSeq = map[string]int64{}
	}
	if st.Tokens == nil {
		st.Tokens = map[string]string{}
	}
	if st.Operators == nil {
		st.Operators = map[string]bool{}
	}
	if st.Idempotency == nil {
		st.Idempotency = map[string]IdemRecord{}
	}
	if st.OpeningBalances == nil {
		st.OpeningBalances = map[string]int64{}
	}
	if st.Revisions == nil {
		st.Revisions = map[string][]Revision{}
	}
	if st.HoldEvents == nil {
		st.HoldEvents = map[string][]HoldEvent{}
	}
	if st.Snapshots == nil {
		st.Snapshots = map[string]StatementSnapshot{}
	}
	if st.AuthorizationTTL == 0 {
		st.AuthorizationTTL = 600
	}
	if st.Next == 0 {
		st.Next = 1
	}
}

func (s *Server) loadPersistentState(ctx context.Context) error {
	result, err := redisCommand(ctx, "GET", persistenceStateKey)
	if err != nil {
		return err
	}
	if string(result) == "null" {
		s.st = emptyState()
		return nil
	}
	var encoded string
	if err := json.Unmarshal(result, &encoded); err != nil {
		return fmt.Errorf("decode persisted value: %w", err)
	}
	var st State
	if err := json.Unmarshal([]byte(encoded), &st); err != nil {
		return fmt.Errorf("decode persisted state: %w", err)
	}
	normalizeState(&st)
	if !s.validState(&st) {
		return errors.New("persisted Pocketful state failed validation")
	}
	s.st = st
	s.ensureLedger()
	return nil
}

func (s *Server) savePersistentState(ctx context.Context) error {
	encoded, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	_, err = redisCommand(ctx, "SET", persistenceStateKey, string(encoded))
	return err
}

func demoAdminAuthorized(r *http.Request) bool {
	secret := os.Getenv("POCKETFUL_DEMO_ADMIN_SECRET")
	if secret == "" {
		// Keep challenge test helpers usable in local development only. On a
		// configured public deployment, set the secret and require it.
		_, _, persistent := persistenceCredentials()
		return !persistent
	}
	return r.Header.Get("X-Pocketful-Demo-Admin") == secret
}

// serve serializes each public request against the durable snapshot. This is
// intentionally simple for the hackathon demo: the existing Stage 4 State
// remains authoritative, while Upstash makes that state survive Vercel instance
// replacement. A distributed lock prevents two instances from overwriting each
// other's wallet mutations.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, _, persistent := persistenceCredentials()
	if !persistent {
		s.serveRequest(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	lockToken, err := acquirePersistenceLock(ctx)
	if err != nil {
		fail(w, ae(http.StatusServiceUnavailable, "persistence_unavailable", "wallet storage is temporarily unavailable"))
		log.Printf("persistence lock error: %v", err)
		return
	}
	defer releasePersistenceLock(context.Background(), lockToken)

	if err := s.loadPersistentState(ctx); err != nil {
		fail(w, ae(http.StatusServiceUnavailable, "persistence_unavailable", "wallet storage is temporarily unavailable"))
		log.Printf("persistence load error: %v", err)
		return
	}

	buffered := newBufferedResponse()
	s.serveRequest(buffered, r)

	if buffered.status < http.StatusInternalServerError {
		if err := s.savePersistentState(ctx); err != nil {
			fail(w, ae(http.StatusServiceUnavailable, "persistence_unavailable", "wallet storage is temporarily unavailable"))
			log.Printf("persistence save error: %v", err)
			return
		}
	}
	buffered.flushTo(w)
}
