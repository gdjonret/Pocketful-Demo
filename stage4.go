package main

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) refundedAmount(paymentID string) int64 {
	var total int64
	for _, p := range s.st.Payments {
		if p.RefundOf != nil && *p.RefundOf == paymentID {
			total += p.Amount
		}
	}
	return total
}

func (s *Server) refund(w http.ResponseWriter, r *http.Request, u *User) {
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
	target := s.st.Payments[parts[1]]
	if target == nil {
		fail(w, ae(404, "not_found", "payment not found"))
		return
	}
	if u.ID != target.ToUserID {
		fail(w, ae(403, "forbidden", "receiver only"))
		return
	}
	if target.RefundOf != nil {
		fail(w, ae(422, "invalid_refund_target", "refund cannot be refunded"))
		return
	}
	a, e := amount(m, "amount")
	if e != nil {
		fail(w, e)
		return
	}
	rs := s.st.Revisions[target.ID]
	current := target.Amount
	if len(rs) > 0 {
		current = rs[len(rs)-1].Amount
	}
	if s.refundedAmount(target.ID)+a > current {
		fail(w, ae(422, "refund_exceeds_payment", "refund exceeds payment"))
		return
	}
	if s.available(u.ID) < a {
		fail(w, ae(409, "insufficient_funds", "insufficient funds"))
		return
	}
	to := s.st.Users[target.FromUserID]
	u.Balance -= a
	to.Balance += a
	s.st.Seq++
	tid := target.ID
	p := &Payment{ID: s.next("p"), FromUserID: u.ID, FromHandle: u.Handle, ToUserID: to.ID, ToHandle: to.Handle, Amount: a, Currency: s.st.Currency, Note: target.Note, Visibility: target.Visibility, CreatedAt: now(), Seq: s.st.Seq, RefundOf: &tid}
	s.st.Payments[p.ID] = p
	s.st.PaymentSeq[p.ID] = p.Seq
	initRevision(&s.st, p)
	s.saveIdem(scope, body, r, p)
	writeJSON(w, 201, p)
}

type batchItem struct {
	p                 *Payment
	expected          int
	amount            int64
	effective, reason string
	effectiveTime     time.Time
}

func (s *Server) correctionBatch(w http.ResponseWriter, r *http.Request, u *User) {
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
	if !s.st.Operators[u.ID] {
		fail(w, ae(403, "forbidden", "operator required"))
		return
	}
	raw, ok := m["corrections"].([]any)
	if !ok || len(raw) < 1 || len(raw) > 32 {
		fail(w, ae(422, "validation_failed", "invalid corrections"))
		return
	}
	items := make([]batchItem, 0, len(raw))
	seen := map[string]bool{}
	for _, x := range raw {
		im, ok := x.(map[string]any)
		if !ok {
			fail(w, ae(422, "validation_failed", "invalid correction"))
			return
		}
		pid, pok := im["payment_id"].(string)
		er, eok := im["expected_revision"].(float64)
		av, aok := im["amount"].(float64)
		eff, tok := im["effective_at"].(string)
		reason, rok := im["reason"].(string)
		if !pok || pid == "" || seen[pid] || !eok || er != float64(int(er)) || er < 1 || !aok || av != float64(int64(av)) || av < 0 || av > 1e9 || !tok || !rok || len([]rune(reason)) < 1 || len([]rune(reason)) > 200 {
			fail(w, ae(422, "validation_failed", "invalid correction"))
			return
		}
		seen[pid] = true
		et, err := parseInstant(eff)
		if err != nil || et.After(time.Now()) {
			fail(w, ae(422, "validation_failed", "invalid correction"))
			return
		}
		p := s.st.Payments[pid]
		if p == nil {
			fail(w, ae(404, "not_found", "payment not found"))
			return
		}
		rs := s.st.Revisions[pid]
		if int(er) != rs[len(rs)-1].Revision {
			fail(w, ae(409, "stale_revision", "stale revision"))
			return
		}
		if p.AuthorizationID != nil || p.RefundOf != nil {
			fail(w, ae(422, "linked_payment_immutable", "linked payment"))
			return
		}
		if int64(av) < s.refundedAmount(pid) {
			fail(w, ae(422, "refund_exceeds_payment", "below refunded amount"))
			return
		}
		items = append(items, batchItem{p, int(er), int64(av), eff, reason, et})
	}
	// Settlement membership and common effective instant.
	for _, it := range items {
		if it.p.SettlementID == nil {
			continue
		}
		sid := *it.p.SettlementID
		for _, p := range s.st.Payments {
			if p.SettlementID != nil && *p.SettlementID == sid && !seen[p.ID] {
				fail(w, ae(422, "incomplete_settlement", "incomplete settlement"))
				return
			}
		}
		for _, other := range items {
			if other.p.SettlementID != nil && *other.p.SettlementID == sid && !other.effectiveTime.Equal(it.effectiveTime) {
				fail(w, ae(422, "validation_failed", "settlement effective times differ"))
				return
			}
		}
	}
	// Combined current deltas, checked against available after all changes.
	deltas := map[string]int64{}
	for _, it := range items {
		last := s.st.Revisions[it.p.ID][len(s.st.Revisions[it.p.ID])-1]
		d := it.amount - last.Amount
		deltas[it.p.FromUserID] -= d
		deltas[it.p.ToUserID] += d
	}
	for id, d := range deltas {
		if s.available(id)+d < 0 {
			fail(w, ae(409, "insufficient_funds", "insufficient funds"))
			return
		}
	}
	old := make(map[string][]Revision, len(items))
	recorded := time.Now().UTC()
	for _, it := range items {
		rs := s.st.Revisions[it.p.ID]
		old[it.p.ID] = rs
		lr, _ := time.Parse(time.RFC3339Nano, rs[len(rs)-1].RecordedAt)
		if !recorded.After(lr) {
			recorded = lr.Add(time.Nanosecond)
		}
	}
	batchID := "cb_" + randomToken()[:24]
	recordedAt := recorded.Format(time.RFC3339Nano)
	revs := make([]Revision, 0, len(items))
	for _, it := range items {
		rs := s.st.Revisions[it.p.ID]
		bid := batchID
		rv := Revision{PaymentID: it.p.ID, Revision: rs[len(rs)-1].Revision + 1, Amount: it.amount, EffectiveAt: it.effective, RecordedAt: recordedAt, Reason: it.reason, CorrectionBatchID: &bid}
		s.st.Revisions[it.p.ID] = append(rs, rv)
		revs = append(revs, rv)
	}
	if !s.historyValid() {
		for id, rs := range old {
			s.st.Revisions[id] = rs
		}
		fail(w, ae(409, "historical_overdraft", "historical overdraft"))
		return
	}
	for id, d := range deltas {
		s.st.Users[id].Balance += d
	}
	res := map[string]any{"correction_batch_id": batchID, "recorded_at": recordedAt, "revisions": revs}
	s.saveIdem(scope, body, r, res)
	writeJSON(w, 201, res)
}
