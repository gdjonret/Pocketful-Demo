#!/usr/bin/env python3
"""Black-box acceptance checks. Run against an already-started container."""
import concurrent.futures
import copy
import json
import os
import urllib.error
import urllib.request

BASE = os.getenv("BASE_URL", "http://127.0.0.1:18080")

def call(method, path, body=None, token=None, key=None):
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode()
        headers["Content-Type"] = "application/json"
    if token: headers["Authorization"] = "Bearer " + token
    if key is not None: headers["Idempotency-Key"] = key
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else None

fixture = {"currency":"EUR","minor_units":2,"settlement_operator_ids":["u_ada"],"users":[
    {"id":"u_ada","email":"ada@example.com","password":"correct horse","display_name":"Ada","handle":"ada","balance":10000},
    {"id":"u_bob","email":"bob@example.com","password":"correct horse","display_name":"Bob","handle":"bob","balance":2500},
    {"id":"u_cy","email":"cy@example.com","password":"correct horse","display_name":"Cy","handle":"cy","balance":0}],"payments":[],"requests":[]}

assert call("GET", "/health") == (200, {"status":"ok"})
assert call("POST", "/_test/reset", fixture)[0] == 204
tokens = {}
for who in ("ada", "bob", "cy"):
    status, result = call("POST", "/auth/login", {"email":who+"@example.com","password":"correct horse"})
    assert status == 200
    tokens[who] = result["token"]
assert call("POST", "/auth/login", {"email":"ada@example.com","password":"wrong password"})[0] == 401
assert call("GET", "/me")[0] == 401
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == 10000

# Validation, defaults, exact Unicode preservation, idempotent replay and conflict.
assert call("POST", "/payments", {"to_handle":"bob","amount":1}, tokens["ada"])[1]["error"]["code"] == "missing_idempotency_key"
s, payment = call("POST", "/payments", {"to_handle":"bob","amount":1500,"note":"dinner 🍜","visibility":"private"}, tokens["ada"], "pay-1")
assert s == 201 and payment["note"] == "dinner 🍜"
assert call("POST", "/payments", {"visibility":"private","note":"dinner 🍜","amount":1500,"to_handle":"bob"}, tokens["ada"], "pay-1") == (200, payment)
assert call("POST", "/payments", {"to_handle":"bob","amount":1}, tokens["ada"], "pay-1")[1]["error"]["code"] == "idempotency_key_reuse"
assert call("POST", "/payments", {"to_handle":"ada","amount":1}, tokens["ada"], "self")[1]["error"]["code"] == "self_payment"
assert call("POST", "/payments", {"to_handle":"bob","amount":0}, tokens["ada"], "zero")[0] == 422

# Feed visibility is exactly public-or-party.
assert payment["payment_id"] in [p["payment_id"] for p in call("GET", "/activity", token=tokens["bob"])[1]["payments"]]
assert payment["payment_id"] not in [p["payment_id"] for p in call("GET", "/activity", token=tokens["cy"])[1]["payments"]]

# Requests may exceed funds; failed pay is unchanged, money arrival enables one payment.
s, request = call("POST", "/requests", {"payer_handle":"cy","amount":2000,"note":"taxi"}, tokens["bob"], "rq-1")
assert s == 201
assert call("POST", f'/requests/{request["request_id"]}/pay', {"visibility":"public"}, tokens["cy"], "rq-pay")[1]["error"]["code"] == "insufficient_funds"
assert call("POST", "/payments", {"to_handle":"cy","amount":2000}, tokens["ada"], "fund-cy")[0] == 201
s, paid = call("POST", f'/requests/{request["request_id"]}/pay', {"visibility":"public"}, tokens["cy"], "rq-pay")
assert s == 201 and paid["request_id"] == request["request_id"]
assert call("POST", f'/requests/{request["request_id"]}/pay', {"visibility":"public"}, tokens["cy"], "rq-pay") == (200, paid)
assert call("POST", f'/requests/{request["request_id"]}/pay', {}, tokens["cy"], "other-key")[1]["error"]["code"] == "request_not_pending"

# Equal splits, order-sensitive remainder, zero shares, and permissions.
s, split = call("POST", "/splits", {"amount":1,"participant_handles":["ada","bob","cy"],"note":"tiny"}, tokens["ada"], "split-1")
assert s == 201 and [x["amount"] for x in split["shares"]] == [1,0,0] and len(split["requests"]) == 2
assert call("POST", f'/requests/{split["requests"][0]["request_id"]}/cancel', {}, tokens["bob"])[0] == 403
assert call("POST", f'/requests/{split["requests"][0]["request_id"]}/cancel', {}, tokens["ada"])[1]["status"] == "cancelled"

# Settlement uses net affordability and commits all members at one timestamp.
settle_body = {"transfers":[{"from_handle":"bob","to_handle":"cy","amount":3000,"visibility":"private"},{"from_handle":"ada","to_handle":"bob","amount":3000}]}
assert call("POST", "/settlements", settle_body, tokens["bob"], "no-op")[0] == 403
s, settlement = call("POST", "/settlements", settle_body, tokens["ada"], "st-1")
assert s == 201 and len(settlement["payments"]) == 2
assert all(p["created_at"] == settlement["committed_at"] for p in settlement["payments"])
assert call("POST", "/settlements", settle_body, tokens["ada"], "st-1") == (200, settlement)

# Concurrent identical requests: exactly one 201, all others identical 200, one movement.
before = call("GET", "/me", token=tokens["ada"])[1]["balance"]
def concurrent_payment(_): return call("POST", "/payments", {"to_handle":"bob","amount":7}, tokens["ada"], "concurrent")
with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
    results = list(pool.map(concurrent_payment, range(25)))
assert [s for s,_ in results].count(201) == 1 and [s for s,_ in results].count(200) == 24
assert len({json.dumps(x, sort_keys=True) for _,x in results}) == 1
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == before - 7

# Export/import restores balances, credentials, tokens, resources and retry receipts.
activity_order = [p["payment_id"] for p in call("GET", "/activity", token=tokens["ada"])[1]["payments"]]
request_order = [q["request_id"] for q in call("GET", "/requests", token=tokens["ada"])[1]["requests"]]
s, exported = call("GET", "/_test/export")
assert s == 200 and exported["track"] == "pocketful" and exported["format_version"] == 1
saved_balance = call("GET", "/me", token=tokens["ada"])[1]["balance"]
tampered = copy.deepcopy(exported)
tampered["state"]["currency"] = "USD"
assert call("POST", "/_test/import", tampered)[0] == 422
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == saved_balance
tampered = copy.deepcopy(exported)
next(iter(tampered["state"]["payments"].values()))["to_user_id"] = "missing-user"
assert call("POST", "/_test/import", tampered)[0] == 422
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == saved_balance
tampered = copy.deepcopy(exported)
payment_ids = list(tampered["state"]["payment_sequence"])
tampered["state"]["payment_sequence"][payment_ids[1]] = tampered["state"]["payment_sequence"][payment_ids[0]]
assert call("POST", "/_test/import", tampered)[0] == 422
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == saved_balance
assert call("POST", "/payments", {"to_handle":"bob","amount":11}, tokens["ada"], "after-export")[0] == 201
assert call("POST", "/_test/import", exported)[0] == 204
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == saved_balance
for _ in range(30):
    assert [p["payment_id"] for p in call("GET", "/activity", token=tokens["ada"])[1]["payments"]] == activity_order
    assert [q["request_id"] for q in call("GET", "/requests", token=tokens["ada"])[1]["requests"]] == request_order
assert call("POST", "/payments", {"to_handle":"bob","amount":7}, tokens["ada"], "concurrent")[0] == 200
assert call("POST", "/auth/login", {"email":"ada@example.com","password":"correct horse"})[0] == 200

# Reset validation is atomic and clears imported tokens/state.
bad = dict(fixture); bad["users"] = [dict(fixture["users"][0], balance=-1)]
assert call("POST", "/_test/reset", bad)[0] == 422
assert call("GET", "/me", token=tokens["ada"])[1]["balance"] == saved_balance
assert call("POST", "/_test/reset", fixture)[0] == 204
assert call("GET", "/me", token=tokens["ada"])[0] == 401

# Malformed/boundary queries and 50-way competing debits preserve nonnegative balances and total.
assert call("POST", "/payments", None, token="bogus", key="x")[0] == 401
assert call("GET", "/activity?limit=4.0", token="bogus")[0] == 401
for who in ("ada", "bob", "cy"):
    tokens[who] = call("POST", "/auth/login", {"email":who+"@example.com","password":"correct horse"})[1]["token"]
assert call("GET", "/activity?limit=4.0", token=tokens["ada"])[0] == 422
assert call("GET", "/requests?offset=-1", token=tokens["ada"])[0] == 422
def competing(i): return call("POST", "/payments", {"to_handle":"bob","amount":300}, tokens["ada"], "race-"+str(i))
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
    race = list(pool.map(competing, range(50)))
assert all(s in (201,409) for s,_ in race) and [s for s,_ in race].count(201) == 33
balances = [call("GET", "/me", token=tokens[x])[1]["balance"] for x in ("ada","bob","cy")]
assert balances == [100,12400,0] and sum(balances) == 12500

print("PASS: health/auth/validation/payments/feed/requests/splits/settlements/concurrency/export-import/reset")
