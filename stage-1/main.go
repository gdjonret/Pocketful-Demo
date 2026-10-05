package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	DisplayName  string `json:"display_name"`
	Handle       string `json:"handle"`
	Balance      int64  `json:"balance"`
}
type Payment struct {
	ID           string  `json:"payment_id"`
	FromUserID   string  `json:"from_user_id"`
	FromHandle   string  `json:"from_handle"`
	ToUserID     string  `json:"to_user_id"`
	ToHandle     string  `json:"to_handle"`
	Amount       int64   `json:"amount"`
	Currency     string  `json:"currency"`
	Note         string  `json:"note"`
	Visibility   string  `json:"visibility"`
	RequestID    *string `json:"request_id"`
	SettlementID *string `json:"settlement_id"`
	CreatedAt    string  `json:"created_at"`
	Seq          int64   `json:"-"`
}
type Request struct {
	ID              string  `json:"request_id"`
	RequesterID     string  `json:"requester_id"`
	RequesterHandle string  `json:"requester_handle"`
	PayerID         string  `json:"payer_id"`
	PayerHandle     string  `json:"payer_handle"`
	Amount          int64   `json:"amount"`
	Currency        string  `json:"currency"`
	Note            string  `json:"note"`
	Status          string  `json:"status"`
	PaymentID       *string `json:"payment_id"`
	CreatedAt       string  `json:"created_at"`
	Seq             int64   `json:"-"`
}
type IdemRecord struct {
	Method, Path, Body string
	Response           json.RawMessage
}
type State struct {
	Currency    string                `json:"currency"`
	MinorUnits  int                   `json:"minor_units"`
	Users       map[string]*User      `json:"users"`
	Payments    map[string]*Payment   `json:"payments"`
	Requests    map[string]*Request   `json:"requests"`
	PaymentSeq  map[string]int64      `json:"payment_sequence"`
	RequestSeq  map[string]int64      `json:"request_sequence"`
	Tokens      map[string]string     `json:"tokens"`
	Operators   map[string]bool       `json:"operators"`
	Idempotency map[string]IdemRecord `json:"idempotency"`
	Next        int64                 `json:"next"`
	Seq         int64                 `json:"seq"`
	SeedTotal   int64                 `json:"seed_total"`
}
type Server struct {
	mu sync.Mutex
	st State
}

const maxSafeInteger int64 = 1<<53 - 1

type apiError struct {
	status    int
	code, msg string
}

func (e *apiError) Error() string               { return e.code }
func ae(status int, code, msg string) *apiError { return &apiError{status, code, msg} }

func emptyState() State {
	return State{Currency: "EUR", MinorUnits: 2, Users: map[string]*User{}, Payments: map[string]*Payment{}, Requests: map[string]*Request{}, PaymentSeq: map[string]int64{}, RequestSeq: map[string]int64{}, Tokens: map[string]string{}, Operators: map[string]bool{}, Idempotency: map[string]IdemRecord{}, Next: 1}
}
func main() {
	s := &Server{st: emptyState()}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serve)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on 0.0.0.0:%s", port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, mux))
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func fail(w http.ResponseWriter, e *apiError) {
	writeJSON(w, e.status, map[string]any{"error": map[string]string{"code": e.code, "message": e.msg}})
}
func decodeObject(r *http.Request) (map[string]any, string, *apiError) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return nil, "", ae(400, "malformed_request", "cannot read body")
	}
	var v any
	if len(b) == 0 || json.Unmarshal(b, &v) != nil {
		return nil, "", ae(400, "malformed_request", "invalid JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "", ae(400, "malformed_request", "body must be an object")
	}
	canon, _ := json.Marshal(v)
	return m, string(canon), nil
}
func str(m map[string]any, k string, req bool) (string, *apiError) {
	v, ok := m[k]
	if !ok {
		if req {
			return "", ae(422, "validation_failed", k+" is required")
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", ae(400, "malformed_request", k+" must be a string")
	}
	return s, nil
}
func amount(m map[string]any, k string) (int64, *apiError) {
	v, ok := m[k]
	if !ok {
		return 0, ae(422, "validation_failed", k+" is required")
	}
	n, ok := v.(float64)
	if !ok || n != float64(int64(n)) || n < 1 || n > 1e9 {
		return 0, ae(422, "validation_failed", "invalid "+k)
	}
	return int64(n), nil
}
func note(m map[string]any) (string, *apiError) {
	v, ok := m["note"]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || len([]rune(s)) > 200 {
		return "", ae(422, "validation_failed", "invalid note")
	}
	return s, nil
}
func visibility(m map[string]any) (string, *apiError) {
	v, ok := m["visibility"]
	if !ok {
		return "public", nil
	}
	s, ok := v.(string)
	if !ok || !(s == "public" || s == "private") {
		return "", ae(422, "validation_failed", "invalid visibility")
	}
	return s, nil
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashPassword(p string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	d := derive([]byte(p), salt, 120000)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(d)
}
func derive(p, s []byte, n int) []byte {
	x := hmac.New(sha256.New, p)
	x.Write(s)
	d := x.Sum(nil)
	for i := 1; i < n; i++ {
		x = hmac.New(sha256.New, p)
		x.Write(d)
		d = x.Sum(nil)
	}
	return d
}
func checkPassword(encoded, p string) bool {
	a := strings.Split(encoded, ":")
	if len(a) != 2 {
		return false
	}
	s, e1 := hex.DecodeString(a[0])
	want, e2 := hex.DecodeString(a[1])
	if e1 != nil || e2 != nil {
		return false
	}
	got := derive([]byte(p), s, 120000)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func validPasswordHash(encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return false
	}
	salt, saltErr := hex.DecodeString(parts[0])
	digest, digestErr := hex.DecodeString(parts[1])
	return saltErr == nil && digestErr == nil && len(salt) == 16 && len(digest) == sha256.Size
}
func (s *Server) userByHandle(h string) *User {
	for _, u := range s.st.Users {
		if u.Handle == h {
			return u
		}
	}
	return nil
}
func (s *Server) userByEmail(e string) *User {
	for _, u := range s.st.Users {
		if u.Email == e {
			return u
		}
	}
	return nil
}
func (s *Server) auth(r *http.Request) (*User, *apiError) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || len(strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))) == 0 {
		return nil, ae(401, "unauthenticated", "valid bearer token required")
	}
	id, ok := s.st.Tokens[strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))]
	if !ok || s.st.Users[id] == nil {
		return nil, ae(401, "unauthenticated", "valid bearer token required")
	}
	return s.st.Users[id], nil
}
func (s *Server) next(prefix string) string {
	for {
		id := fmt.Sprintf("%s_%d", prefix, s.st.Next)
		s.st.Next++
		_, userExists := s.st.Users[id]
		_, paymentExists := s.st.Payments[id]
		_, requestExists := s.st.Requests[id]
		if !userExists && !paymentExists && !requestExists {
			return id
		}
	}
}
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/health" && r.Method == "GET" {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/_test/reset" && r.Method == "POST" {
		s.reset(w, r)
		return
	}
	if r.URL.Path == "/_test/export" && r.Method == "GET" {
		writeJSON(w, 200, map[string]any{"track": "pocketful", "format_version": 1, "state": s.st})
		return
	}
	if r.URL.Path == "/_test/import" && r.Method == "POST" {
		s.importState(w, r)
		return
	}
	if r.URL.Path == "/auth/signup" && r.Method == "POST" {
		s.signup(w, r)
		return
	}
	if r.URL.Path == "/auth/login" && r.Method == "POST" {
		s.login(w, r)
		return
	}
	u, e := s.auth(r)
	if e != nil {
		fail(w, e)
		return
	}
	switch {
	case r.URL.Path == "/me" && r.Method == "GET":
		writeJSON(w, 200, map[string]any{"user_id": u.ID, "display_name": u.DisplayName, "handle": u.Handle, "balance": u.Balance, "currency": s.st.Currency, "minor_units": s.st.MinorUnits})
	case r.URL.Path == "/payments" && r.Method == "POST":
		s.payment(w, r, u)
	case r.URL.Path == "/requests" && r.Method == "POST":
		s.createRequest(w, r, u)
	case r.URL.Path == "/requests" && r.Method == "GET":
		s.listRequests(w, r, u)
	case strings.HasPrefix(r.URL.Path, "/requests/") && r.Method == "POST":
		s.requestAction(w, r, u)
	case r.URL.Path == "/splits" && r.Method == "POST":
		s.split(w, r, u)
	case r.URL.Path == "/activity" && r.Method == "GET":
		s.activity(w, r, u)
	case r.URL.Path == "/settlements" && r.Method == "POST":
		s.settlement(w, r, u)
	default:
		fail(w, ae(404, "not_found", "not found"))
	}
}
func (s *Server) idem(r *http.Request, u *User, body string) (string, *IdemRecord, *apiError) {
	k := r.Header.Get("Idempotency-Key")
	if k == "" {
		return "", nil, ae(400, "missing_idempotency_key", "idempotency key required")
	}
	if len(k) > 255 {
		return "", nil, ae(422, "validation_failed", "invalid idempotency key")
	}
	scope := u.ID + "\x00" + r.Method + "\x00" + r.URL.Path + "\x00" + k
	if rec, ok := s.st.Idempotency[scope]; ok {
		if rec.Body != body {
			return "", nil, ae(409, "idempotency_key_reuse", "key reused with different body")
		}
		return scope, &rec, nil
	}
	return scope, nil, nil
}
func replay(w http.ResponseWriter, rec *IdemRecord) {
	var v any
	_ = json.Unmarshal(rec.Response, &v)
	writeJSON(w, 200, v)
}
func (s *Server) saveIdem(scope, body string, r *http.Request, v any) {
	b, _ := json.Marshal(v)
	s.st.Idempotency[scope] = IdemRecord{r.Method, r.URL.Path, body, b}
}
func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	m, _, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	cur, ok := m["currency"].(string)
	if !ok || !(cur == "EUR" || cur == "JPY" || cur == "BHD") {
		fail(w, ae(422, "validation_failed", "invalid currency"))
		return
	}
	mu, ok := m["minor_units"].(float64)
	if !ok || !(mu == 0 || mu == 2 || mu == 3) {
		fail(w, ae(422, "validation_failed", "invalid minor_units"))
		return
	}
	arr, ok := m["users"].([]any)
	if !ok {
		fail(w, ae(422, "validation_failed", "invalid users"))
		return
	}
	ns := emptyState()
	ns.Currency = cur
	ns.MinorUnits = int(mu)
	handles := map[string]bool{}
	emails := map[string]bool{}
	for _, x := range arr {
		um, ok := x.(map[string]any)
		if !ok {
			fail(w, ae(422, "validation_failed", "invalid user"))
			return
		}
		id, iok := um["id"].(string)
		email, eok := um["email"].(string)
		pw, pok := um["password"].(string)
		dn, dok := um["display_name"].(string)
		h, hok := um["handle"].(string)
		b, bok := um["balance"].(float64)
		if !iok || !eok || !pok || !dok || !hok || !bok || id == "" || len(id) > 64 || !handleRE.MatchString(h) || b != float64(int64(b)) || b < 0 || b > float64(maxSafeInteger) || handles[h] || emails[email] {
			fail(w, ae(422, "validation_failed", "invalid user fixture"))
			return
		}
		u := &User{id, email, hashPassword(pw), dn, h, int64(b)}
		ns.Users[id] = u
		handles[h] = true
		emails[email] = true
		if ns.SeedTotal > math.MaxInt64-int64(b) {
			fail(w, ae(422, "validation_failed", "seed total exceeds arithmetic range"))
			return
		}
		ns.SeedTotal += int64(b)
	}
	loadPayments := func() bool {
		a, ok := m["payments"]
		if !ok {
			return true
		}
		xs, ok := a.([]any)
		if !ok {
			return false
		}
		for _, x := range xs {
			pm, ok := x.(map[string]any)
			if !ok {
				return false
			}
			id, _ := pm["id"].(string)
			f, _ := pm["from_user_id"].(string)
			t, _ := pm["to_user_id"].(string)
			am, aok := pm["amount"].(float64)
			n, _ := pm["note"].(string)
			v, _ := pm["visibility"].(string)
			if id == "" || ns.Users[f] == nil || ns.Users[t] == nil || !aok || am != float64(int64(am)) || am < 1 || !(v == "public" || v == "private") {
				return false
			}
			ns.Seq++
			ns.Payments[id] = &Payment{id, f, ns.Users[f].Handle, t, ns.Users[t].Handle, int64(am), cur, n, v, nil, nil, now(), ns.Seq}
			ns.PaymentSeq[id] = ns.Seq
		}
		return true
	}
	loadRequests := func() bool {
		a, ok := m["requests"]
		if !ok {
			return true
		}
		xs, ok := a.([]any)
		if !ok {
			return false
		}
		for _, x := range xs {
			rm, ok := x.(map[string]any)
			if !ok {
				return false
			}
			id, _ := rm["id"].(string)
			rq, _ := rm["requester_id"].(string)
			py, _ := rm["payer_id"].(string)
			am, aok := rm["amount"].(float64)
			n, _ := rm["note"].(string)
			st, _ := rm["status"].(string)
			if id == "" || ns.Users[rq] == nil || ns.Users[py] == nil || !aok || am != float64(int64(am)) || am < 0 || !validStatus(st) {
				return false
			}
			ns.Seq++
			ns.Requests[id] = &Request{id, rq, ns.Users[rq].Handle, py, ns.Users[py].Handle, int64(am), cur, n, st, nil, now(), ns.Seq}
			ns.RequestSeq[id] = ns.Seq
		}
		return true
	}
	if !loadPayments() || !loadRequests() {
		fail(w, ae(422, "validation_failed", "invalid fixture"))
		return
	}
	if ops, ok := m["settlement_operator_ids"]; ok {
		xs, ok := ops.([]any)
		if !ok {
			fail(w, ae(422, "validation_failed", "invalid operators"))
			return
		}
		for _, x := range xs {
			id, ok := x.(string)
			if !ok || ns.Users[id] == nil {
				fail(w, ae(422, "validation_failed", "invalid operator"))
				return
			}
			ns.Operators[id] = true
		}
	}
	s.st = ns
	w.WriteHeader(204)
}
func validStatus(x string) bool {
	return x == "pending" || x == "paid" || x == "declined" || x == "cancelled"
}
func (s *Server) importState(w http.ResponseWriter, r *http.Request) {
	m, _, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	if m["track"] != "pocketful" || m["format_version"] != float64(1) {
		fail(w, ae(422, "validation_failed", "invalid export envelope"))
		return
	}
	b, err := json.Marshal(m["state"])
	if err != nil {
		fail(w, ae(422, "validation_failed", "invalid state"))
		return
	}
	var ns State
	if json.Unmarshal(b, &ns) != nil || ns.Currency == "" || ns.Users == nil || ns.Payments == nil || ns.Requests == nil || ns.PaymentSeq == nil || ns.RequestSeq == nil || ns.Tokens == nil || ns.Idempotency == nil || ns.Operators == nil {
		fail(w, ae(422, "validation_failed", "invalid state"))
		return
	}
	for id, p := range ns.Payments {
		if p != nil {
			p.Seq = ns.PaymentSeq[id]
		}
	}
	for id, q := range ns.Requests {
		if q != nil {
			q.Seq = ns.RequestSeq[id]
		}
	}
	if !s.validState(&ns) {
		fail(w, ae(422, "validation_failed", "invalid state"))
		return
	}
	s.st = ns
	w.WriteHeader(204)
}
func (s *Server) validState(st *State) bool {
	expectedMinorUnits := map[string]int{"EUR": 2, "JPY": 0, "BHD": 3}
	minorUnits, currencyOK := expectedMinorUnits[st.Currency]
	if !currencyOK || st.MinorUnits != minorUnits || st.Next < 1 || st.Seq < 0 || st.SeedTotal < 0 {
		return false
	}
	var total int64
	handles := map[string]bool{}
	emails := map[string]bool{}
	for id, u := range st.Users {
		if u == nil || u.ID != id || id == "" || len(id) > 64 || !emailRE.MatchString(u.Email) || !validPasswordHash(u.PasswordHash) || !handleRE.MatchString(u.Handle) || u.Balance < 0 || u.Balance > maxSafeInteger || handles[u.Handle] || emails[u.Email] {
			return false
		}
		handles[u.Handle] = true
		emails[u.Email] = true
		if total > math.MaxInt64-u.Balance {
			return false
		}
		total += u.Balance
	}
	if total != st.SeedTotal {
		return false
	}
	if len(st.PaymentSeq) != len(st.Payments) || len(st.RequestSeq) != len(st.Requests) {
		return false
	}
	sequences := map[int64]bool{}
	for id, p := range st.Payments {
		if p == nil {
			return false
		}
		from, to := st.Users[p.FromUserID], st.Users[p.ToUserID]
		sequence, sequenceOK := st.PaymentSeq[id]
		if p.ID != id || id == "" || len(id) > 64 || from == nil || to == nil || from.ID == to.ID || p.FromHandle != from.Handle || p.ToHandle != to.Handle || p.Amount < 1 || p.Amount > 1000000000 || p.Currency != st.Currency || len([]rune(p.Note)) > 200 || (p.Visibility != "public" && p.Visibility != "private") || !sequenceOK || sequence < 1 || sequence > st.Seq || p.Seq != sequence || sequences[sequence] {
			return false
		}
		sequences[sequence] = true
		if _, err := time.Parse(time.RFC3339Nano, p.CreatedAt); err != nil {
			return false
		}
		if p.RequestID != nil {
			q := st.Requests[*p.RequestID]
			if q == nil || q.Status != "paid" || q.PaymentID == nil || *q.PaymentID != p.ID || q.PayerID != p.FromUserID || q.RequesterID != p.ToUserID || q.Amount != p.Amount {
				return false
			}
		}
		if p.SettlementID != nil && (*p.SettlementID == "" || len(*p.SettlementID) > 64 || p.RequestID != nil) {
			return false
		}
	}
	for id, q := range st.Requests {
		if q == nil {
			return false
		}
		rq, py := st.Users[q.RequesterID], st.Users[q.PayerID]
		sequence, sequenceOK := st.RequestSeq[id]
		if q.ID != id || id == "" || len(id) > 64 || rq == nil || py == nil || rq.ID == py.ID || q.RequesterHandle != rq.Handle || q.PayerHandle != py.Handle || q.Amount < 0 || q.Amount > 1000000000 || q.Currency != st.Currency || len([]rune(q.Note)) > 200 || !validStatus(q.Status) || !sequenceOK || sequence < 1 || sequence > st.Seq || q.Seq != sequence || sequences[sequence] {
			return false
		}
		sequences[sequence] = true
		if _, err := time.Parse(time.RFC3339Nano, q.CreatedAt); err != nil {
			return false
		}
		if q.Status == "paid" {
			if q.PaymentID == nil || st.Payments[*q.PaymentID] == nil {
				return false
			}
		} else if q.PaymentID != nil {
			return false
		}
	}
	for token, userID := range st.Tokens {
		if token == "" || st.Users[userID] == nil {
			return false
		}
	}
	for userID, enabled := range st.Operators {
		if !enabled || st.Users[userID] == nil {
			return false
		}
	}
	for scope, record := range st.Idempotency {
		parts := strings.Split(scope, "\x00")
		var body any
		var response any
		if len(parts) != 4 || st.Users[parts[0]] == nil || parts[1] != record.Method || parts[2] != record.Path || parts[3] == "" || len(parts[3]) > 255 || record.Method != "POST" || json.Unmarshal([]byte(record.Body), &body) != nil || json.Unmarshal(record.Response, &response) != nil {
			return false
		}
		if _, ok := body.(map[string]any); !ok {
			return false
		}
		if _, ok := response.(map[string]any); !ok {
			return false
		}
	}
	return true
}

var emailRE = regexp.MustCompile(`^[^@]+@[^@]+$`)
var handleRE = regexp.MustCompile(`^[a-z0-9_]{1,20}$`)
var nonHandle = regexp.MustCompile(`[^a-z0-9_]`)

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	m, _, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	email, e := str(m, "email", true)
	if e != nil {
		fail(w, e)
		return
	}
	pw, e := str(m, "password", true)
	if e != nil {
		fail(w, e)
		return
	}
	dn, e := str(m, "display_name", true)
	if e != nil {
		fail(w, e)
		return
	}
	if !emailRE.MatchString(email) || len(pw) < 8 || dn == "" {
		fail(w, ae(422, "validation_failed", "invalid signup"))
		return
	}
	if s.userByEmail(email) != nil {
		fail(w, ae(409, "email_taken", "email already registered"))
		return
	}
	local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
	h := nonHandle.ReplaceAllString(local, "_")
	if len(h) > 20 {
		h = h[:20]
	}
	if h == "" {
		fail(w, ae(422, "validation_failed", "cannot derive handle"))
		return
	}
	if s.userByHandle(h) != nil {
		fail(w, ae(409, "handle_taken", "handle already taken"))
		return
	}
	id := s.next("u")
	tok := randomToken()
	s.st.Users[id] = &User{id, email, hashPassword(pw), dn, h, 0}
	s.st.Tokens[tok] = id
	writeJSON(w, 201, map[string]any{"user_id": id, "display_name": dn, "token": tok})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	m, _, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	email, e := str(m, "email", true)
	if e != nil {
		fail(w, e)
		return
	}
	pw, e := str(m, "password", true)
	if e != nil {
		fail(w, e)
		return
	}
	u := s.userByEmail(email)
	if u == nil || !checkPassword(u.PasswordHash, pw) {
		fail(w, ae(401, "unauthenticated", "invalid credentials"))
		return
	}
	tok := randomToken()
	s.st.Tokens[tok] = u.ID
	writeJSON(w, 200, map[string]any{"user_id": u.ID, "display_name": u.DisplayName, "token": tok})
}
func (s *Server) payment(w http.ResponseWriter, r *http.Request, u *User) {
	m, body, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	scope, rec, e := s.idem(r, u, body)
	if e != nil {
		fail(w, e)
		return
	}
	if rec != nil {
		replay(w, rec)
		return
	}
	h, e := str(m, "to_handle", true)
	if e != nil {
		fail(w, e)
		return
	}
	a, e := amount(m, "amount")
	if e != nil {
		fail(w, e)
		return
	}
	n, e := note(m)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := visibility(m)
	if e != nil {
		fail(w, e)
		return
	}
	to := s.userByHandle(h)
	if to == nil {
		fail(w, ae(404, "not_found", "recipient not found"))
		return
	}
	if to.ID == u.ID {
		fail(w, ae(422, "self_payment", "cannot pay self"))
		return
	}
	if u.Balance < a {
		fail(w, ae(409, "insufficient_funds", "insufficient funds"))
		return
	}
	if to.Balance > maxSafeInteger-a {
		fail(w, ae(422, "validation_failed", "balance would exceed arithmetic range"))
		return
	}
	p := s.move(u, to, a, n, v, nil, nil)
	s.saveIdem(scope, body, r, p)
	writeJSON(w, 201, p)
}
func (s *Server) move(from, to *User, a int64, n, v string, rid, sid *string) *Payment {
	from.Balance -= a
	to.Balance += a
	s.st.Seq++
	p := &Payment{s.next("p"), from.ID, from.Handle, to.ID, to.Handle, a, s.st.Currency, n, v, rid, sid, now(), s.st.Seq}
	s.st.Payments[p.ID] = p
	s.st.PaymentSeq[p.ID] = p.Seq
	return p
}
func (s *Server) createRequest(w http.ResponseWriter, r *http.Request, u *User) {
	m, body, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	scope, rec, e := s.idem(r, u, body)
	if e != nil {
		fail(w, e)
		return
	}
	if rec != nil {
		replay(w, rec)
		return
	}
	h, e := str(m, "payer_handle", true)
	if e != nil {
		fail(w, e)
		return
	}
	a, e := amount(m, "amount")
	if e != nil {
		fail(w, e)
		return
	}
	n, e := note(m)
	if e != nil {
		fail(w, e)
		return
	}
	py := s.userByHandle(h)
	if py == nil {
		fail(w, ae(404, "not_found", "payer not found"))
		return
	}
	if py.ID == u.ID {
		fail(w, ae(422, "self_request", "cannot request self"))
		return
	}
	q := s.newRequest(u, py, a, n)
	s.saveIdem(scope, body, r, q)
	writeJSON(w, 201, q)
}
func (s *Server) newRequest(rq, py *User, a int64, n string) *Request {
	s.st.Seq++
	q := &Request{s.next("rq"), rq.ID, rq.Handle, py.ID, py.Handle, a, s.st.Currency, n, "pending", nil, now(), s.st.Seq}
	s.st.Requests[q.ID] = q
	s.st.RequestSeq[q.ID] = q.Seq
	return q
}
func (s *Server) requestAction(w http.ResponseWriter, r *http.Request, u *User) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 {
		fail(w, ae(404, "not_found", "not found"))
		return
	}
	q := s.st.Requests[parts[1]]
	if q == nil {
		fail(w, ae(404, "not_found", "request not found"))
		return
	}
	switch parts[2] {
	case "pay":
		m, body, e := decodeObject(r)
		if e != nil {
			fail(w, e)
			return
		}
		scope, rec, e := s.idem(r, u, body)
		if e != nil {
			fail(w, e)
			return
		}
		if rec != nil {
			replay(w, rec)
			return
		}
		if u.ID != q.PayerID {
			fail(w, ae(403, "forbidden", "only payer may pay"))
			return
		}
		v, e := visibility(m)
		if e != nil {
			fail(w, e)
			return
		}
		if q.Status != "pending" {
			fail(w, ae(409, "request_not_pending", "request is not pending"))
			return
		}
		if u.Balance < q.Amount {
			fail(w, ae(409, "insufficient_funds", "insufficient funds"))
			return
		}
		if s.st.Users[q.RequesterID].Balance > maxSafeInteger-q.Amount {
			fail(w, ae(422, "validation_failed", "balance would exceed arithmetic range"))
			return
		}
		rid := q.ID
		p := s.move(u, s.st.Users[q.RequesterID], q.Amount, q.Note, v, &rid, nil)
		q.Status = "paid"
		q.PaymentID = &p.ID
		s.saveIdem(scope, body, r, p)
		writeJSON(w, 201, p)
	case "decline":
		if u.ID != q.PayerID {
			fail(w, ae(403, "forbidden", "only payer may decline"))
			return
		}
		if q.Status == "declined" {
			writeJSON(w, 200, q)
			return
		}
		if q.Status != "pending" {
			fail(w, ae(409, "request_not_pending", "request is not pending"))
			return
		}
		q.Status = "declined"
		writeJSON(w, 200, q)
	case "cancel":
		if u.ID != q.RequesterID {
			fail(w, ae(403, "forbidden", "only requester may cancel"))
			return
		}
		if q.Status == "cancelled" {
			writeJSON(w, 200, q)
			return
		}
		if q.Status != "pending" {
			fail(w, ae(409, "request_not_pending", "request is not pending"))
			return
		}
		q.Status = "cancelled"
		writeJSON(w, 200, q)
	default:
		fail(w, ae(404, "not_found", "not found"))
	}
}
func page(r *http.Request) (int, int, *apiError) {
	limit, offset := 50, 0
	for k, d := range map[string]*int{"limit": &limit, "offset": &offset} {
		if raw := r.URL.Query().Get(k); raw != "" {
			if !regexp.MustCompile(`^[0-9]+$`).MatchString(raw) {
				return 0, 0, ae(422, "validation_failed", "invalid "+k)
			}
			n, e := strconv.Atoi(raw)
			if e != nil {
				return 0, 0, ae(422, "validation_failed", "invalid "+k)
			}
			*d = n
		}
	}
	if limit < 1 || limit > 200 || offset < 0 {
		return 0, 0, ae(422, "validation_failed", "invalid pagination")
	}
	return limit, offset, nil
}
func (s *Server) listRequests(w http.ResponseWriter, r *http.Request, u *User) {
	limit, off, e := page(r)
	if e != nil {
		fail(w, e)
		return
	}
	dir := r.URL.Query().Get("direction")
	status := r.URL.Query().Get("status")
	if dir != "" && dir != "incoming" && dir != "outgoing" {
		fail(w, ae(422, "validation_failed", "invalid direction"))
		return
	}
	if status != "" && !validStatus(status) {
		fail(w, ae(422, "validation_failed", "invalid status"))
		return
	}
	xs := []*Request{}
	for _, q := range s.st.Requests {
		if q.RequesterID != u.ID && q.PayerID != u.ID {
			continue
		}
		if dir == "incoming" && q.PayerID != u.ID {
			continue
		}
		if dir == "outgoing" && q.RequesterID != u.ID {
			continue
		}
		if status != "" && q.Status != status {
			continue
		}
		xs = append(xs, q)
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].Seq > xs[j].Seq })
	end := off + limit
	if end > len(xs) {
		end = len(xs)
	}
	out := []*Request{}
	if off < len(xs) {
		out = xs[off:end]
	}
	writeJSON(w, 200, map[string]any{"requests": out, "has_more": end < len(xs)})
}
func (s *Server) activity(w http.ResponseWriter, r *http.Request, u *User) {
	limit, off, e := page(r)
	if e != nil {
		fail(w, e)
		return
	}
	xs := []*Payment{}
	for _, p := range s.st.Payments {
		if p.Visibility == "public" || p.FromUserID == u.ID || p.ToUserID == u.ID {
			xs = append(xs, p)
		}
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].Seq > xs[j].Seq })
	end := off + limit
	if end > len(xs) {
		end = len(xs)
	}
	out := []*Payment{}
	if off < len(xs) {
		out = xs[off:end]
	}
	writeJSON(w, 200, map[string]any{"payments": out, "has_more": end < len(xs)})
}
func (s *Server) split(w http.ResponseWriter, r *http.Request, u *User) {
	m, body, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	scope, rec, e := s.idem(r, u, body)
	if e != nil {
		fail(w, e)
		return
	}
	if rec != nil {
		replay(w, rec)
		return
	}
	a, e := amount(m, "amount")
	if e != nil {
		fail(w, e)
		return
	}
	n, e := note(m)
	if e != nil {
		fail(w, e)
		return
	}
	raw, ok := m["participant_handles"].([]any)
	if !ok || len(raw) == 0 {
		fail(w, ae(422, "validation_failed", "invalid participants"))
		return
	}
	hs := []string{}
	seen := map[string]bool{}
	for _, x := range raw {
		h, ok := x.(string)
		if !ok || seen[h] {
			fail(w, ae(422, "validation_failed", "invalid participants"))
			return
		}
		seen[h] = true
		hs = append(hs, h)
	}
	users := []*User{}
	for _, h := range hs {
		x := s.userByHandle(h)
		if x == nil {
			fail(w, ae(404, "not_found", "participant not found"))
			return
		}
		users = append(users, x)
	}
	base := a / int64(len(users))
	extra := a % int64(len(users))
	shares := []map[string]any{}
	reqs := []*Request{}
	for i, x := range users {
		share := base
		if int64(i) < extra {
			share++
		}
		shares = append(shares, map[string]any{"handle": x.Handle, "amount": share})
		if x.ID != u.ID {
			reqs = append(reqs, s.newRequest(u, x, share, n))
		}
	}
	res := map[string]any{"split_id": s.next("sp"), "amount": a, "currency": s.st.Currency, "note": n, "shares": shares, "requests": reqs, "created_at": now()}
	s.saveIdem(scope, body, r, res)
	writeJSON(w, 201, res)
}
func (s *Server) settlement(w http.ResponseWriter, r *http.Request, u *User) {
	m, body, e := decodeObject(r)
	if e != nil {
		fail(w, e)
		return
	}
	scope, rec, e := s.idem(r, u, body)
	if e != nil {
		fail(w, e)
		return
	}
	if rec != nil {
		replay(w, rec)
		return
	}
	if !s.st.Operators[u.ID] {
		fail(w, ae(403, "forbidden", "operator required"))
		return
	}
	raw, ok := m["transfers"].([]any)
	if !ok || len(raw) < 1 || len(raw) > 32 {
		fail(w, ae(422, "validation_failed", "invalid transfers"))
		return
	}
	type tx struct {
		f, t *User
		a    int64
		n, v string
	}
	txs := []tx{}
	delta := map[string]int64{}
	for _, x := range raw {
		tm, ok := x.(map[string]any)
		if !ok {
			fail(w, ae(422, "validation_failed", "invalid transfer"))
			return
		}
		fh, e := str(tm, "from_handle", true)
		if e != nil {
			fail(w, e)
			return
		}
		th, e := str(tm, "to_handle", true)
		if e != nil {
			fail(w, e)
			return
		}
		a, e := amount(tm, "amount")
		if e != nil {
			fail(w, e)
			return
		}
		n, e := note(tm)
		if e != nil {
			fail(w, e)
			return
		}
		v, e := visibility(tm)
		if e != nil {
			fail(w, e)
			return
		}
		f, t := s.userByHandle(fh), s.userByHandle(th)
		if f == nil || t == nil {
			fail(w, ae(404, "not_found", "wallet not found"))
			return
		}
		if f.ID == t.ID {
			fail(w, ae(422, "self_payment", "cannot transfer to self"))
			return
		}
		txs = append(txs, tx{f, t, a, n, v})
		delta[f.ID] -= a
		delta[t.ID] += a
	}
	for id, d := range delta {
		if s.st.Users[id].Balance+d < 0 {
			fail(w, ae(409, "insufficient_funds", "settlement not affordable"))
			return
		}
		if d > 0 && s.st.Users[id].Balance > maxSafeInteger-d {
			fail(w, ae(422, "validation_failed", "balance would exceed arithmetic range"))
			return
		}
	}
	sid := s.next("st")
	committed := now()
	ps := []*Payment{}
	for id, d := range delta {
		s.st.Users[id].Balance += d
	}
	for _, t := range txs {
		s.st.Seq++
		p := &Payment{s.next("p"), t.f.ID, t.f.Handle, t.t.ID, t.t.Handle, t.a, s.st.Currency, t.n, t.v, nil, &sid, committed, s.st.Seq}
		s.st.Payments[p.ID] = p
		s.st.PaymentSeq[p.ID] = p.Seq
		ps = append(ps, p)
	}
	res := map[string]any{"settlement_id": sid, "committed_at": committed, "payments": ps}
	s.saveIdem(scope, body, r, res)
	writeJSON(w, 201, res)
}
