import httpx, uuid, sys, json
C = httpx.Client(base_url=sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000", timeout=30)
U = lambda: str(uuid.uuid4())
TRACE, PARENT = "a" * 32, "b" * 16

def mk(run):
    tr = "\n".join(f"[ev_{i:04d}] line {i}" for i in range(40))
    tools = ["query_metrics", "fetch_logs", "rollback_deployment", "scale_service", "page_owner", "disable_feature"]
    return {"profile": "ga5-incident-agent/v2", "runId": run, "agentName": "incident-response",
            "publicMarker": "mk-" + run, "sensitive": {"accessToken": "CANARY-" + run, "privateNote": "CANARY-n-" + run},
            "incident": {"incidentId": "INC-1", "title": "t", "service": "checkout", "severity": "SEV-1",
                         "transcript": tr, "allowedRootCauses": ["bad_deploy", "db_saturation"]},
            "toolCatalog": [{"name": n, "description": n, "inputSchema": {"type": "object"}} for n in tools],
            "policy": {"maximumDiagnostics": 3, "effectTools": ["rollback_deployment", "scale_service", "page_owner"],
                       "approvalRequiredFor": ["rollback_deployment", "disable_feature"], "doNotExport": ["accessToken"]}}

def attrs(s): return {a["key"]: list(a["value"].values())[0] for a in s["attributes"]}

def run(scn):
    rid_ = "run-" + uuid.uuid4().hex[:10]; body = mk(rid_)
    hdr = {"traceparent": f"00-{TRACE}-{PARENT}-01", "tracestate": "vendor=x"}
    r = C.post("/v2/incidents", json=body, headers=hdr); assert r.status_code == 200, r.text
    d, n, first = r.json(), 0, None
    while d["status"] == "waiting":
        n += 1; assert n < 10
        if d["approvals"]:
            ap = d["approvals"][0]; assert not d["dispatches"]
            p = {"receiptId": U(), "approvals": [{"approvalId": ap["approvalId"], "decision": "approved", "nonce": U()}]}
        else:
            outs = []
            for x in d["dispatches"]:
                first = first or x["actionId"]
                o = {"actionId": x["actionId"], "callId": x["callId"], "attempt": x["attempt"], "status": 200, "resultClass": "ok", "nonce": U()}
                if scn == "retry" and x["actionId"] == first and x["attempt"] == 1: o.update(status=503, resultClass="unavailable")
                if scn == "timeout" and x["actionId"] == first: o = {**o, "status": 0, "errorType": "timeout"}; o.pop("resultClass")
                outs.append(o)
            p = {"receiptId": U(), "outcomes": outs}
        r = C.post(f"/v2/incidents/{rid_}/receipts", json=p); assert r.status_code == 200, r.text
        assert C.post(f"/v2/incidents/{rid_}/receipts", json=p).json() == r.json(), "replay differs"
        assert C.post(f"/v2/incidents/{rid_}/receipts", json={**p, "extra": 1}).status_code == 409
        d = r.json()
    check(body, d, scn, rid_)
    print("OK", scn, d["status"], d.get("chosenEffect"))

def check(body, d, scn, rid_):
    raw = json.dumps(d); assert "CANARY" not in raw
    assert C.get(f"/v2/incidents/{rid_}").json() == d
    assert C.post("/v2/incidents", json=body).json() == d
    assert C.post("/v2/incidents", json={**body, "publicMarker": "x"}).status_code == 409
    assert C.post("/v2/incidents", json={**body, "runId": "new-run-1", "profile": "bad"}).status_code in (400, 422)
    assert C.get("/v2/incidents/new-run-1").status_code == 404
    assert not d["dispatches"] and not d["approvals"]
    S = d["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert {s["traceId"] for s in S} == {TRACE}
    ids = [s["spanId"] for s in S]; assert len(ids) == len(set(ids)) and all(i != "0" * 16 for i in ids)
    byn = lambda p: [s for s in S if s["name"].startswith(p)]
    srv = byn("POST /v2")[0]; assert srv["kind"] == 2 and srv["parentSpanId"] == PARENT
    assert len(byn("chat incident-plan")) == 1 and byn("chat incident-plan")[0]["kind"] == 3
    acts = {a["actionId"] for a in d["actionLog"]}
    assert len(byn("execute_tool")) == len(acts)
    clients = byn("POST tool/"); assert len(clients) == len(d["actionLog"])
    for s in S:
        a = attrs(s); assert a["ga5.run.id"] == rid_ and a["ga5.public.marker"] == "mk-" + rid_
        assert not any(k.endswith(("arguments", "result")) for k in a)
    cs = {attrs(s)["ga5.action.id"] + str(attrs(s)["ga5.attempt"]): s for s in clients}
    for x in d["actionLog"]:
        sid = x["traceparent"].split("-")[2]; s = next(c for c in clients if c["spanId"] == sid)
        a = attrs(s); assert int(a["ga5.attempt"]) == x["attempt"] and int(a["http.request.resend_count"]) == x["attempt"] - 1
        assert x["tracestate"] == "vendor=x"
        st = s.get("status", {}).get("code", 0)
        if "error.type" in a: assert st == 2
        else: assert st != 2
    diags = [x for x in d["actionLog"] if x["phase"] == "diagnostic" and x["attempt"] == 1]
    assert len(byn("incident.join")) == (1 if len(diags) > 1 else 0)
    if scn == "timeout":
        assert not [x for x in d["actionLog"] if x["phase"] == "effect"] and d["suppressed"]
    else:
        eff = [x for x in d["actionLog"] if x["phase"] == "effect"]; assert len(eff) == 1
        if "approvalId" in eff[0]:
            rc = next(r for r in d["receiptLog"] if r.get("approvalId") == eff[0]["approvalId"])
            assert rc["nonce"] == eff[0]["approvalNonce"] and len(byn("approval_gate")) == 1
            assert eff[0]["actionId"] in acts

for scn in ("happy", "retry", "timeout"): run(scn)