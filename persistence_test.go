package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeRedis struct {
	mu     sync.Mutex
	values map[string]string
}

func TestPersistenceCredentialsPreferVercelKV(t *testing.T) {
	t.Setenv("KV_REST_API_URL", "https://vercel-kv.example/")
	t.Setenv("KV_REST_API_TOKEN", "vercel-token")
	t.Setenv("UPSTASH_REDIS_REST_URL", "https://stale-upstash.example/")
	t.Setenv("UPSTASH_REDIS_REST_TOKEN", "stale-token")

	url, token, ok := persistenceCredentials()
	if !ok || url != "https://vercel-kv.example" || token != "vercel-token" {
		t.Fatalf("credentials=(%q, %q, %v), want Vercel KV credentials", url, token, ok)
	}
}

func (f *fakeRedis) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var cmd []any
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil || len(cmd) == 0 {
		http.Error(w, "bad command", 400)
		return
	}
	name, _ := cmd[0].(string)
	switch strings.ToUpper(name) {
	case "GET":
		key := cmd[1].(string)
		if v, ok := f.values[key]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": v})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": nil})
		}
	case "SET":
		key, value := cmd[1].(string), cmd[2].(string)
		nx := false
		for _, arg := range cmd[3:] {
			if s, ok := arg.(string); ok && strings.EqualFold(s, "NX") {
				nx = true
			}
		}
		if nx {
			if _, exists := f.values[key]; exists {
				_ = json.NewEncoder(w).Encode(map[string]any{"result": nil})
				return
			}
		}
		f.values[key] = value
		_ = json.NewEncoder(w).Encode(map[string]any{"result": "OK"})
	case "EVAL":
		// The production script only deletes the lock when the token matches.
		key := cmd[3].(string)
		token := cmd[4].(string)
		if f.values[key] == token {
			delete(f.values, key)
			_ = json.NewEncoder(w).Encode(map[string]any{"result": 1})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": 0})
		}
	default:
		http.Error(w, "unsupported", 400)
	}
}

func TestPersistentSignupSurvivesServerReplacement(t *testing.T) {
	redis := &fakeRedis{values: map[string]string{}}
	ts := httptest.NewServer(redis)
	defer ts.Close()
	t.Setenv("UPSTASH_REDIS_REST_URL", ts.URL)
	t.Setenv("UPSTASH_REDIS_REST_TOKEN", "test-token")
	t.Setenv("POCKETFUL_DEMO_ADMIN_SECRET", "admin-test")

	first := &Server{st: emptyState()}
	signup := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(`{"email":"demo@example.com","password":"Password123!","display_name":"Demo"}`))
	signup.Header.Set("Content-Type", "application/json")
	signupRec := httptest.NewRecorder()
	first.serve(signupRec, signup)
	if signupRec.Code != http.StatusCreated {
		t.Fatalf("signup status=%d body=%s", signupRec.Code, signupRec.Body.String())
	}
	if got := first.st.Users["u_1"].Balance; got != demoStartingBalance {
		t.Fatalf("new demo account balance=%d, want %d", got, demoStartingBalance)
	}

	// Simulate Vercel replacing the process with a completely fresh Server.
	second := &Server{st: emptyState()}
	login := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"demo@example.com","password":"Password123!"}`))
	login.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	second.serve(loginRec, login)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login after replacement status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
}

func TestPublicTestEndpointsAreHiddenWhenPersistenceEnabled(t *testing.T) {
	redis := &fakeRedis{values: map[string]string{}}
	ts := httptest.NewServer(redis)
	defer ts.Close()
	t.Setenv("UPSTASH_REDIS_REST_URL", ts.URL)
	t.Setenv("UPSTASH_REDIS_REST_TOKEN", "test-token")
	t.Setenv("POCKETFUL_DEMO_ADMIN_SECRET", "admin-test")

	s := &Server{st: emptyState()}
	req := httptest.NewRequest(http.MethodGet, "/_test/export", nil)
	rec := httptest.NewRecorder()
	s.serve(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("public export status=%d, want 404", rec.Code)
	}
}
