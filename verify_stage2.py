#!/usr/bin/env python3
import concurrent.futures, copy, datetime, json, os, time, urllib.error, urllib.request
BASE=os.getenv("BASE_URL","http://127.0.0.1:18081")
def call(method,path,body=None,token=None,key=None,accept=None):
    h={};data=None
    if body is not None:data=json.dumps(body).encode();h["Content-Type"]="application/json"
    if token:h["Authorization"]="Bearer "+token
    if key is not None:h["Idempotency-Key"]=key
    if accept:h["Accept"]=accept
    q=urllib.request.Request(BASE+path,data=data,headers=h,method=method)
    try:
        with urllib.request.urlopen(q,timeout=10) as r:
            raw=r.read();return r.status,(json.loads(raw) if raw and "json" in r.headers.get("Content-Type","") else raw.decode()),r.headers
    except urllib.error.HTTPError as e:
        raw=e.read();return e.code,(json.loads(raw) if raw else None),e.headers
future=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=2)).isoformat()
fixture={"currency":"EUR","minor_units":2,"authorization_ttl_seconds":2,"settlement_operator_ids":["u_a"],"users":[{"id":"u_a","email":"a@example.com","password":"correct horse","display_name":"Ada","handle":"ada","balance":10000},{"id":"u_b","email":"b@example.com","password":"correct horse","display_name":"Bob","handle":"bob","balance":2000},{"id":"u_c","email":"c@example.com","password":"correct horse","display_name":"Cy","handle":"cy","balance":500}],"payments":[],"requests":[],"authorizations":[{"id":"a_seed","from_user_id":"u_a","to_user_id":"u_b","amount":1000,"note":"seed hold","visibility":"private","status":"open","expires_at":future}]}
assert call("POST","/_test/reset",fixture)[0]==204
tok={x:call("POST","/auth/login",{"email":x[0]+"@example.com","password":"correct horse"})[1]["token"] for x in ("ada","bob","cy")}
me=call("GET","/me",token=tok["ada"])[1];assert (me["balance"],me["total"],me["held"],me["available"])==(10000,10000,1000,9000)
assert call("GET","/requests",token=tok["ada"],accept="text/html")[0]==200
s,html,h=call("GET","/authorizations",token=tok["ada"],accept="text/html");assert s==200 and "authorization-list" in html and "text/html" in h["Content-Type"]
s,a,_=call("POST","/authorizations",{"to_handle":"bob","amount":3000,"note":"deposit","visibility":"public"},tok["ada"],"auth-1");assert s==201 and a["remaining_amount"]==3000
assert call("POST","/authorizations",{"to_handle":"bob","amount":3000,"note":"deposit","visibility":"public"},tok["ada"],"auth-1")[:2]==(200,a)
me=call("GET","/me",token=tok["ada"])[1];assert (me["total"],me["held"],me["available"])==(10000,4000,6000)
assert call("POST","/payments",{"to_handle":"cy","amount":6001},tok["ada"],"blocked")[1]["error"]["code"]=="insufficient_funds"
assert call("GET","/activity",token=tok["ada"])[1]["payments"]==[]
s,p1,_=call("POST",f'/authorizations/{a["authorization_id"]}/capture',{"amount":700,"final":False},tok["bob"],"cap-1");assert s==201 and p1["authorization_id"]==a["authorization_id"]
assert call("POST",f'/authorizations/{a["authorization_id"]}/capture',{"amount":700,"final":False},tok["bob"],"cap-1")[:2]==(200,p1)
current=call("GET","/authorizations",token=tok["ada"])[1]["authorizations"][0];assert current["status"]=="open" and current["captured_amount"]==700 and current["remaining_amount"]==2300
s,p2,_=call("POST",f'/authorizations/{a["authorization_id"]}/capture',{"amount":500},tok["bob"],"cap-2");assert s==201
current=call("GET","/authorizations",token=tok["ada"])[1]["authorizations"][0];assert current["status"]=="captured" and current["captured_amount"]==1200 and current["remaining_amount"]==0 and current["payment_ids"]==[p1["payment_id"],p2["payment_id"]]
assert call("POST",f'/authorizations/{a["authorization_id"]}/capture',{},tok["bob"],"cap-3")[1]["error"]["code"]=="authorization_not_open"
me=call("GET","/me",token=tok["ada"])[1];assert (me["total"],me["held"],me["available"])==(8800,1000,7800)
s,v,_=call("POST","/authorizations",{"to_handle":"cy","amount":500},tok["ada"],"void-auth");assert s==201
assert call("POST",f'/authorizations/{v["authorization_id"]}/void',{},tok["bob"])[0]==403
assert call("POST",f'/authorizations/{v["authorization_id"]}/void',{},tok["ada"])[1]["status"]=="voided"
s,c,_=call("POST","/authorizations",{"to_handle":"bob","amount":1000},tok["ada"],"race-auth");assert s==201
def cap(i):return call("POST",f'/authorizations/{c["authorization_id"]}/capture',{"amount":100,"final":False},tok["bob"],"race-cap-"+str(i))[0]
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool: statuses=list(pool.map(cap,range(20)))
assert statuses.count(201)==10 and all(x in (201,409) for x in statuses)
s,e,_=call("POST","/authorizations",{"to_handle":"bob","amount":200},tok["ada"],"expiry");assert s==201
time.sleep(2.2)
expired=[x for x in call("GET","/authorizations",token=tok["ada"])[1]["authorizations"] if x["authorization_id"]==e["authorization_id"]][0];assert expired["status"]=="expired" and expired["remaining_amount"]==0
assert call("POST",f'/authorizations/{e["authorization_id"]}/capture',{},tok["bob"],"expired-cap")[1]["error"]["code"]=="authorization_expired"
exported=call("GET","/_test/export")[1];before=call("GET","/me",token=tok["ada"])[1]
contradictory=copy.deepcopy(exported)
record=contradictory["state"]["authorizations"][a["authorization_id"]]
record["payment_ids"]=[];record["payment_id"]=None;record["captured_amount"]=0
assert call("POST","/_test/import",contradictory)[0]==422
assert call("GET","/me",token=tok["ada"])[1]==before
assert call("POST","/_test/import",exported)[0]==204
assert call("GET","/me",token=tok["ada"])[1]==before
assert call("POST",f'/authorizations/{a["authorization_id"]}/capture',{"amount":700,"final":False},tok["bob"],"cap-1")[:2]==(200,p1)
balances=[call("GET","/me",token=tok[x])[1]["total"] for x in ("ada","bob","cy")];assert sum(balances)==12500 and all(call("GET","/me",token=tok[x])[1]["available"]>=0 for x in ("ada","bob","cy"))
# Fixture-valid historical closed authorizations have no required capture receipt metadata.
closed=dict(fixture);closed["authorizations"]=[{"id":"seed_closed","from_user_id":"u_a","to_user_id":"u_b","amount":50,"note":"","visibility":"public","status":"captured","expires_at":future}]
assert call("POST","/_test/reset",closed)[0]==204
closed_export=call("GET","/_test/export")[1]
assert call("POST","/_test/import",closed_export)[0]==204
restored=call("GET","/authorizations",token=call("POST","/auth/login",{"email":"a@example.com","password":"correct horse"})[1]["token"])[1]["authorizations"][0]
assert restored["authorization_id"]=="seed_closed" and restored["status"]=="captured" and restored["captured_amount"]==0 and restored["payment_id"] is None
print("PASS: stage2 holds/captures/expiry/idempotency/concurrency/export-import/content-negotiation")
