package main

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

func parseInstant(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || (!strings.Contains(v, "Z") && !strings.ContainsAny(v[10:], "+-")) {
		return time.Time{}, ae(422, "validation_failed", "invalid instant")
	}
	return t, nil
}

func (s *Server) ensureLedger() {
	if s.st.Revisions == nil {
		s.st.Revisions = map[string][]Revision{}
	}
	if s.st.OpeningBalances == nil {
		s.st.OpeningBalances = map[string]int64{}
	}
	if s.st.HoldEvents == nil {
		s.st.HoldEvents = map[string][]HoldEvent{}
	}
	if s.st.Snapshots == nil {
		s.st.Snapshots = map[string]StatementSnapshot{}
	}
	if s.st.ResetAt == "" {
		s.st.ResetAt = now()
	}
	for id, p := range s.st.Payments {
		if len(s.st.Revisions[id]) == 0 {
			s.st.Revisions[id] = []Revision{{PaymentID: id, Revision: 1, Amount: p.Amount, EffectiveAt: p.CreatedAt, RecordedAt: p.CreatedAt, Reason: ""}}
		}
	}
	if len(s.st.OpeningBalances) == 0 && len(s.st.Users) > 0 {
		for id, u := range s.st.Users {
			s.st.OpeningBalances[id] = u.Balance
		}
		for id, p := range s.st.Payments {
			rs := s.st.Revisions[id]
			a := p.Amount
			if len(rs) > 0 {
				a = rs[len(rs)-1].Amount
			}
			s.st.OpeningBalances[p.FromUserID] += a
			s.st.OpeningBalances[p.ToUserID] -= a
		}
	}
	for id, a := range s.st.Authorizations {
		if len(s.st.HoldEvents[id]) != 0 {
			continue
		}
		capturePayments := make([]*Payment, 0, len(a.PaymentIDs))
		seen := map[string]bool{}
		for _, paymentID := range a.PaymentIDs {
			if p := s.st.Payments[paymentID]; p != nil && p.AuthorizationID != nil && *p.AuthorizationID == id {
				capturePayments = append(capturePayments, p)
				seen[p.ID] = true
			}
		}
		// Stage 2 exports normally carry payment_ids, but accept the equivalent
		// reverse links too so migration does not depend on redundant metadata.
		for _, p := range s.st.Payments {
			if p.AuthorizationID != nil && *p.AuthorizationID == id && !seen[p.ID] {
				capturePayments = append(capturePayments, p)
			}
		}
		sort.Slice(capturePayments, func(i, j int) bool {
			ti, _ := time.Parse(time.RFC3339Nano, capturePayments[i].CreatedAt)
			tj, _ := time.Parse(time.RFC3339Nano, capturePayments[j].CreatedAt)
			if ti.Equal(tj) {
				return capturePayments[i].ID < capturePayments[j].ID
			}
			return ti.Before(tj)
		})
		if a.Status == "open" || len(capturePayments) > 0 {
			remaining := a.Amount
			events := []HoldEvent{{At: a.CreatedAt, RecordedAt: a.CreatedAt, Remaining: remaining}}
			for i, p := range capturePayments {
				remaining -= p.Amount
				if remaining < 0 {
					remaining = 0
				}
				if a.Status != "open" && i == len(capturePayments)-1 {
					remaining = 0
				}
				events = append(events, HoldEvent{At: p.CreatedAt, RecordedAt: p.CreatedAt, Remaining: remaining})
			}
			s.st.HoldEvents[id] = events
			if a.Status != "open" && len(capturePayments) > 0 && a.ClosedAt == nil {
				x := capturePayments[len(capturePayments)-1].CreatedAt
				a.ClosedAt = &x
			}
		} else if a.Status == "expired" && a.ClosedAt == nil {
			x := a.ExpiresAt
			a.ClosedAt = &x
		}
	}
}

func selected(rs []Revision, known *time.Time) *Revision {
	var out *Revision
	for i := range rs {
		t, _ := time.Parse(time.RFC3339Nano, rs[i].RecordedAt)
		if known == nil || !t.After(*known) {
			x := rs[i]
			out = &x
		}
	}
	return out
}
func (s *Server) balanceAt(uid string, at time.Time, known *time.Time, inclusive bool) int64 {
	b := s.st.OpeningBalances[uid]
	for id, p := range s.st.Payments {
		r := selected(s.st.Revisions[id], known)
		if r == nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, r.EffectiveAt)
		applies := t.Before(at) || (inclusive && t.Equal(at))
		if applies {
			if p.FromUserID == uid {
				b -= r.Amount
			}
			if p.ToUserID == uid {
				b += r.Amount
			}
		}
	}
	return b
}
func (s *Server) heldAt(uid string, at time.Time, known *time.Time) int64 {
	var held int64
	for id, a := range s.st.Authorizations {
		if a.FromUserID != uid {
			continue
		}
		ct, _ := time.Parse(time.RFC3339Nano, a.CreatedAt)
		if ct.After(at) || (known != nil && ct.After(*known)) {
			continue
		}
		rem := int64(0)
		for _, e := range s.st.HoldEvents[id] {
			et, _ := time.Parse(time.RFC3339Nano, e.At)
			rt, _ := time.Parse(time.RFC3339Nano, e.RecordedAt)
			if !et.After(at) && (known == nil || !rt.After(*known)) {
				rem = e.Remaining
			}
		}
		exp, _ := time.Parse(time.RFC3339Nano, a.ExpiresAt)
		if !exp.After(at) {
			rem = 0
		}
		held += rem
	}
	return held
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, u *User) {
	s.ensureLedger()
	q := r.URL.Query()
	asRaw, asSet := q["as_of"]
	knownRaw, knownSet := q["known_at"]
	var at time.Time
	var known *time.Time
	if asSet {
		if len(asRaw) != 1 || asRaw[0] == "" {
			fail(w, ae(422, "validation_failed", "invalid as_of"))
			return
		}
		x, e := parseInstant(asRaw[0])
		if e != nil {
			fail(w, e.(*apiError))
			return
		}
		at = x
	} else {
		at = time.Now()
	}
	if knownSet {
		if len(knownRaw) != 1 || knownRaw[0] == "" {
			fail(w, ae(422, "validation_failed", "invalid known_at"))
			return
		}
		x, e := parseInstant(knownRaw[0])
		if e != nil {
			fail(w, e.(*apiError))
			return
		}
		known = &x
	}
	total := u.Balance
	held := s.held(u.ID)
	if asSet || knownSet {
		total = s.balanceAt(u.ID, at, known, true)
		held = s.heldAt(u.ID, at, known)
	}
	out := map[string]any{"user_id": u.ID, "display_name": u.DisplayName, "handle": u.Handle, "balance": total, "total": total, "available": total - held, "held": held, "currency": s.st.Currency, "minor_units": s.st.MinorUnits}
	if asSet {
		out["as_of"] = asRaw[0]
	}
	if knownSet {
		out["known_at"] = knownRaw[0]
	}
	writeJSON(w, 200, out)
}

func (s *Server) buildSnapshot(uid string, from *time.Time, to time.Time, known *time.Time, fromRaw, toRaw string, knownRaw *string) StatementSnapshot {
	opening := s.st.OpeningBalances[uid]
	if from != nil {
		opening = s.balanceAt(uid, *from, known, false)
	}
	closing := s.balanceAt(uid, to, known, false)
	type pair struct {
		p *Payment
		r Revision
	}
	all := []pair{}
	for id, p := range s.st.Payments {
		if p.FromUserID != uid && p.ToUserID != uid {
			continue
		}
		rv := selected(s.st.Revisions[id], known)
		if rv == nil {
			continue
		}
		et, _ := time.Parse(time.RFC3339Nano, rv.EffectiveAt)
		if from != nil && et.Before(*from) {
			continue
		}
		if !et.Before(to) {
			continue
		}
		all = append(all, pair{p, *rv})
	}
	sort.Slice(all, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, all[i].r.EffectiveAt)
		tj, _ := time.Parse(time.RFC3339Nano, all[j].r.EffectiveAt)
		if ti.Equal(tj) {
			return all[i].p.ID < all[j].p.ID
		}
		return ti.Before(tj)
	})
	bal := opening
	entries := make([]StatementEntry, 0, len(all))
	for _, x := range all {
		d := x.r.Amount
		if x.p.FromUserID == uid {
			d = -d
		}
		bal += d
		cp := *x.p
		cp.Amount = x.r.Amount
		entries = append(entries, StatementEntry{cp, d, bal, x.r.Revision, x.r.EffectiveAt, x.r.RecordedAt})
	}
	var fp *string
	if fromRaw != "" {
		fp = &fromRaw
	}
	return StatementSnapshot{uid, opening, closing, entries, fp, toRaw, knownRaw}
}
func statementPage(w http.ResponseWriter, snap StatementSnapshot, token string, limit, offset int) {
	end := offset + limit
	if end > len(snap.Entries) {
		end = len(snap.Entries)
	}
	items := []StatementEntry{}
	if offset < len(snap.Entries) {
		items = snap.Entries[offset:end]
	}
	out := map[string]any{"opening_balance": snap.OpeningBalance, "entries": items, "closing_balance": snap.ClosingBalance, "has_more": end < len(snap.Entries), "snapshot": token}
	if snap.From != nil {
		out["from"] = *snap.From
	}
	out["to"] = snap.To
	if snap.KnownAt != nil {
		out["known_at"] = *snap.KnownAt
	}
	writeJSON(w, 200, out)
}
func (s *Server) statement(w http.ResponseWriter, r *http.Request, u *User) {
	s.ensureLedger()
	limit, offset, e := page(r)
	if e != nil {
		fail(w, e)
		return
	}
	q := r.URL.Query()
	if tok := q.Get("snapshot"); tok != "" {
		if q.Has("from") || q.Has("to") || q.Has("known_at") {
			fail(w, ae(422, "validation_failed", "snapshot parameters"))
			return
		}
		snap, ok := s.st.Snapshots[tok]
		if !ok || snap.UserID != u.ID {
			fail(w, ae(404, "not_found", "snapshot not found"))
			return
		}
		statementPage(w, snap, tok, limit, offset)
		return
	}
	var from *time.Time
	fr := q.Get("from")
	if q.Has("from") {
		x, er := parseInstant(fr)
		if er != nil || fr == "" {
			fail(w, ae(422, "validation_failed", "invalid from"))
			return
		}
		from = &x
	}
	tr := q.Get("to")
	to := time.Now()
	if q.Has("to") {
		x, er := parseInstant(tr)
		if er != nil || tr == "" {
			fail(w, ae(422, "validation_failed", "invalid to"))
			return
		}
		to = x
	} else {
		tr = to.UTC().Format(time.RFC3339Nano)
	}
	if from != nil && !from.Before(to) {
		fail(w, ae(422, "validation_failed", "invalid window"))
		return
	}
	var known *time.Time
	var kr *string
	if q.Has("known_at") {
		v := q.Get("known_at")
		x, er := parseInstant(v)
		if er != nil || v == "" {
			fail(w, ae(422, "validation_failed", "invalid known_at"))
			return
		}
		known = &x
		kr = &v
	}
	snap := s.buildSnapshot(u.ID, from, to, known, fr, tr, kr)
	tok := randomToken()
	s.st.Snapshots[tok] = snap
	statementPage(w, snap, tok, limit, offset)
}

func (s *Server) listRevisions(w http.ResponseWriter, r *http.Request, u *User) {
	s.ensureLedger()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 {
		fail(w, ae(404, "not_found", "not found"))
		return
	}
	p := s.st.Payments[parts[1]]
	if p == nil || (u.ID != p.FromUserID && u.ID != p.ToUserID) {
		fail(w, ae(404, "not_found", "not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"revisions": s.st.Revisions[p.ID]})
}

func (s *Server) correction(w http.ResponseWriter, r *http.Request, u *User) {
	s.ensureLedger()
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
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 {
		fail(w, ae(404, "not_found", "not found"))
		return
	}
	p := s.st.Payments[parts[1]]
	if p == nil {
		fail(w, ae(404, "not_found", "not found"))
		return
	}
	if p.FromUserID != u.ID {
		fail(w, ae(403, "forbidden", "sender only"))
		return
	}
	if p.SettlementID != nil || p.AuthorizationID != nil || p.RefundOf != nil {
		fail(w, ae(422, "linked_payment_immutable", "linked payment"))
		return
	}
	er, ok := m["expected_revision"].(float64)
	av, aok := m["amount"].(float64)
	eff, eok := m["effective_at"].(string)
	reason, rok := m["reason"].(string)
	et, terr := parseInstant(eff)
	if !ok || er != float64(int(er)) || er < 1 || !aok || av != float64(int64(av)) || av < 0 || av > 1e9 || !eok || terr != nil || et.After(time.Now()) || !rok || len([]rune(reason)) < 1 || len([]rune(reason)) > 200 {
		fail(w, ae(422, "validation_failed", "invalid correction"))
		return
	}
	rs := s.st.Revisions[p.ID]
	last := rs[len(rs)-1]
	if int(er) != last.Revision {
		fail(w, ae(409, "stale_revision", "stale revision"))
		return
	}
	newAmount := int64(av)
	if newAmount < s.refundedAmount(p.ID) {
		fail(w, ae(422, "refund_exceeds_payment", "amount below refunded total"))
		return
	}
	diff := newAmount - last.Amount
	if diff > 0 && s.available(p.FromUserID) < diff {
		fail(w, ae(409, "insufficient_funds", "insufficient funds"))
		return
	}
	if diff < 0 && s.available(p.ToUserID) < (-diff) {
		fail(w, ae(409, "insufficient_funds", "insufficient funds"))
		return
	}
	recorded := time.Now().UTC()
	lr, _ := time.Parse(time.RFC3339Nano, last.RecordedAt)
	if !recorded.After(lr) {
		recorded = lr.Add(time.Nanosecond)
	}
	rv := Revision{PaymentID: p.ID, Revision: last.Revision + 1, Amount: newAmount, EffectiveAt: eff, RecordedAt: recorded.Format(time.RFC3339Nano), Reason: reason}
	s.st.Revisions[p.ID] = append(rs, rv)
	if !s.historyValid() {
		s.st.Revisions[p.ID] = rs
		fail(w, ae(409, "historical_overdraft", "historical overdraft"))
		return
	}
	s.st.Users[p.FromUserID].Balance -= diff
	s.st.Users[p.ToUserID].Balance += diff
	s.saveIdem(scope, body, r, rv)
	writeJSON(w, 201, rv)
}
func (s *Server) historyValid() bool {
	times := map[time.Time]bool{}
	for _, rs := range s.st.Revisions {
		if len(rs) > 0 {
			t, _ := time.Parse(time.RFC3339Nano, rs[len(rs)-1].EffectiveAt)
			times[t] = true
		}
	}
	for _, es := range s.st.HoldEvents {
		for _, e := range es {
			t, _ := time.Parse(time.RFC3339Nano, e.At)
			times[t] = true
		}
	}
	for _, a := range s.st.Authorizations {
		t, e := time.Parse(time.RFC3339Nano, a.ExpiresAt)
		if e == nil {
			times[t] = true
		}
	}
	ts := make([]time.Time, 0, len(times))
	for t := range times {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	for _, t := range ts {
		for id := range s.st.Users {
			b := s.balanceAt(id, t, nil, true)
			if b < 0 || b-s.heldAt(id, t, nil) < 0 {
				return false
			}
		}
	}
	return true
}

func initRevision(st *State, p *Payment) {
	if st.Revisions == nil {
		st.Revisions = map[string][]Revision{}
	}
	st.Revisions[p.ID] = []Revision{{PaymentID: p.ID, Revision: 1, Amount: p.Amount, EffectiveAt: p.CreatedAt, RecordedAt: p.CreatedAt, Reason: ""}}
}
