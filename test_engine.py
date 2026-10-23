"""Model-free tests of the receipt state machine and the OTLP trace rules. Run: python test_engine.py"""
import json
import uuid

import engine

APPROVAL = ["rollback_deployment", "disable_feature"]


def new(diags, effect, traceparent=None, tracestate=None):
    req = {"runId": "run_" + uuid.uuid4().hex[:12], "publicMarker": "PUBLIC_x", "agentName": "incident-response",
           "policy": {"approvalRequiredFor": APPROVAL}}
    plan = {"rootCause": "c", "evidence": ["ev_a", "ev_b"], "source": "model",
            "diagnostics": [{"toolName": t, "arguments": {"service": "s"}, "evidence": ["ev_a"]} for t in diags],
            "effect": {"toolName": effect, "arguments": {"service": "s"}, "evidence": ["ev_b"]}, "alternateEffect": None}
    meta = {"start": engine.now_ns(), "end": engine.now_ns() + 1_000_000, "model": "gemini-x", "provider": "gcp.gemini",
            "ok": True}
    ctx = {"traceId": traceparent.split("-")[1], "parentSpanId": traceparent.split("-")[2], "tracestate": tracestate} \
        if traceparent else {"traceId": engine.trace_id(), "parentSpanId": None, "tracestate": None}
    st, issued, _ = engine.new_run(req, plan, meta, ctx, engine.now_ns())
    return st, issued


def outcome(d, status, **kw):
    return {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": status,
            "nonce": str(uuid.uuid4()), **kw}


def receipt(st, outcomes=None, approvals=None):
    body = {"receiptId": "rc_" + uuid.uuid4().hex[:10]}
    if outcomes is not None:
        body["outcomes"] = outcomes
    if approvals is not None:
        body["approvals"] = approvals
    return engine.apply_receipt(st, body["receiptId"], body)


def rejects(st, **kw):
    try:
        receipt(st, **kw)
    except engine.InvalidTransition:
        return True
    return False


def attr(s, k):
    for a in s["attributes"]:
        if a["key"] == k:
            return next(iter(a["value"].values()))
    return None


def check_trace(st, expect_join, expect_gate, traceparent=None, tracestate=None):
    doc = engine.view(st)
    spans = doc["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    ids = {s["spanId"]: s for s in spans}
    assert len(ids) == len(spans), "duplicate span ids"
    tid = spans[0]["traceId"]
    assert all(s["traceId"] == tid for s in spans)
    names = [s["name"] for s in spans]
    assert names.count("POST /v2/incidents") == 1 and names.count("chat incident-plan") == 1
    assert names.count("invoke_agent incident-response") == 1
    assert names.count("incident.join") == (1 if expect_join else 0), names
    assert names.count("approval_gate") == (1 if expect_gate else 0), names
    server = next(s for s in spans if s["kind"] == 2)
    if traceparent:
        assert tid == traceparent.split("-")[1] and server["parentSpanId"] == traceparent.split("-")[2]
        assert all(s.get("traceState") == tracestate for s in spans)
    for s in spans:
        assert attr(s, "ga5.run.id") == st["runId"] and attr(s, "ga5.public.marker") == "PUBLIC_x"
        assert s is server or s.get("parentSpanId") in ids, f"orphan {s['name']}"
        assert int(s["endTimeUnixNano"]) >= int(s["startTimeUnixNano"])
    executed = [a for a in st["actions"] if a["attempts"]]
    assert sum(n.startswith("execute_tool ") for n in names) == len(executed)
    for d in doc["actionLog"]:
        c = ids[d["traceparent"].split("-")[2]]
        assert c["kind"] == 3 and c["name"] == f"POST tool/{d['toolName']}"
        assert attr(c, "ga5.attempt") == d["attempt"] and attr(c, "http.request.resend_count") == d["attempt"] - 1
        assert ids[c["parentSpanId"]]["name"] == f"execute_tool {d['toolName']}"
        r = next(x for x in doc["receiptLog"] if x.get("actionId") == d["actionId"] and x["attempt"] == d["attempt"])
        assert attr(c, "ga5.receipt.id") == r["receiptId"] and attr(c, "ga5.receipt.nonce") == r["nonce"]
        if r["status"] == 503:
            assert c["status"]["code"] == 2 and attr(c, "error.type") == "503"
        elif r["status"] == 0:
            assert c["status"]["code"] == 2 and attr(c, "error.type") == "timeout"
        else:
            assert c["status"]["code"] != 2 and attr(c, "error.type") is None
    if expect_join:
        join = next(s for s in spans if s["name"] == "incident.join")
        diag_spans = {a["spanId"] for a in st["actions"] if a["phase"] == "diagnostic"}
        assert {l["spanId"] for l in join["links"]} == diag_spans and join["parentSpanId"] == st["trace"]["agentSpanId"]
    if expect_gate and st["approval"]["decision"]:
        gate = next(s for s in spans if s["name"] == "approval_gate")
        assert attr(gate, "ga5.approval.id") == st["approval"]["approvalId"]
        assert attr(gate, "ga5.approval.nonce") == st["approval"]["nonce"]
    json.dumps(doc)
    return doc


def test_simple_scale():
    st, d = new(["query_metrics"], "scale_service")
    assert rejects(st, approvals=[{"approvalId": "apr_nope00000", "decision": "approved", "nonce": "n"}])
    st, d2, a = receipt(st, [outcome(d[0], 200, resultClass="diagnosis_confirmed")])
    assert len(d2) == 1 and d2[0]["phase"] == "effect" and not a
    assert rejects(st, outcomes=[outcome(d[0], 200)])  # no longer pending
    st, d3, _ = receipt(st, [outcome(d2[0], 200, resultClass="effect_applied")])
    assert st["status"] == "completed" and st["chosenEffect"] == "scale_service" and not d3
    assert rejects(st, outcomes=[outcome(d2[0], 200)])  # terminal
    check_trace(st, False, False)


def test_parallel_with_retry_and_join():
    tp = "00-" + uuid.uuid4().hex + "-" + uuid.uuid4().hex[:16] + "-01"
    st, d = new(["query_logs", "read_runbook"], "page_owner", tp, "vendor=abc")
    assert all(x.get("tracestate") == "vendor=abc" for x in d)
    assert rejects(st, outcomes=[outcome(d[0], 200), outcome(d[0], 200)])  # duplicate in one receipt
    st, r1, a = receipt(st, [outcome(d[0], 503), outcome(d[1], 200, resultClass="diagnosis_confirmed")])
    assert len(r1) == 1 and r1[0]["attempt"] == 2 and r1[0]["actionId"] == d[0]["actionId"] and not a
    assert r1[0]["traceparent"] != d[0]["traceparent"] and r1[0]["callId"] == d[0]["callId"]
    st, r2, _ = receipt(st, [outcome(r1[0], 200, resultClass="diagnosis_confirmed")])
    assert r2 and r2[0]["toolName"] == "page_owner"
    st, _, _ = receipt(st, [outcome(r2[0], 200)])
    assert st["status"] == "completed"
    check_trace(st, True, False, tp, "vendor=abc")


def test_double_503_fails():
    st, d = new(["query_metrics"], "scale_service")
    st, r1, _ = receipt(st, [outcome(d[0], 503)])
    st, r2, _ = receipt(st, [outcome(r1[0], 503)])
    assert not r2 and st["status"] == "failed" and st["suppressed"] == ["scale_service"]
    assert not any(x["phase"] == "effect" for x in st["actionLog"])
    check_trace(st, False, False)


def test_timeout_suppresses_effect():
    st, d = new(["query_logs", "read_runbook"], "page_owner")
    st, r, a = receipt(st, [outcome(d[0], 200, resultClass="diagnosis_confirmed"),
                            outcome(d[1], 0, errorType="timeout")])
    assert not r and not a and st["status"] == "failed" and st["chosenEffect"] is None
    assert st["suppressed"] == ["page_owner"]
    check_trace(st, True, False)


def test_timeout_then_pending_sibling():
    st, d = new(["query_logs", "read_runbook"], "page_owner")
    st, r, _ = receipt(st, [outcome(d[1], 0, errorType="timeout")])
    assert st["status"] == "waiting" and not r  # sibling still pending
    st, r, _ = receipt(st, [outcome(d[0], 503)])  # doomed run: no retry
    assert not r and st["status"] == "failed"
    check_trace(st, True, False)


def test_approval_flow_with_effect_retry():
    st, d = new(["inspect_deployment"], "rollback_deployment")
    st, r, a = receipt(st, [outcome(d[0], 200, resultClass="diagnosis_confirmed")])
    assert not r and len(a) == 1
    apr = a[0]
    assert apr["argumentsDigest"] == engine.args_digest({"service": "s"}) and len(apr["argumentsDigest"]) == 64
    effect_action = next(x for x in st["actions"] if x["phase"] == "effect")
    assert apr["actionId"] == effect_action["actionId"]
    assert rejects(st, approvals=[{"approvalId": "apr_wrong0000", "decision": "approved", "nonce": "n"}])
    nonce = str(uuid.uuid4())
    st, r, a = receipt(st, approvals=[{"approvalId": apr["approvalId"], "decision": "approved", "nonce": nonce}])
    assert len(r) == 1 and not a and r[0]["approvalId"] == apr["approvalId"] and r[0]["approvalNonce"] == nonce
    assert r[0]["actionId"] == apr["actionId"]
    st, r2, a2 = receipt(st, [outcome(r[0], 503)])
    assert len(r2) == 1 and not a2 and r2[0]["attempt"] == 2 and r2[0]["approvalNonce"] == nonce
    st, _, _ = receipt(st, [outcome(r2[0], 200, resultClass="effect_applied")])
    assert st["status"] == "completed" and st["chosenEffect"] == "rollback_deployment"
    doc = check_trace(st, False, True)
    shapes = [sorted(x) for x in doc["receiptLog"]]
    assert ["approvalId", "decision", "nonce", "receiptId"] in shapes


def test_approval_rejected():
    st, d = new(["query_logs"], "disable_feature")
    st, _, a = receipt(st, [outcome(d[0], 200)])
    st, r, _ = receipt(st, approvals=[{"approvalId": a[0]["approvalId"], "decision": "rejected", "nonce": "n1"}])
    assert not r and st["status"] == "failed" and st["suppressed"] == ["disable_feature"]
    assert not any(x["phase"] == "effect" for x in st["actionLog"])
    check_trace(st, False, True)


def test_views():
    st, d = new(["query_metrics"], "scale_service")
    w = engine.view(st)
    assert w["status"] == "waiting" and "chosenEffect" not in w and w["dispatches"] == d and "otlp" in w
    st, r, _ = receipt(st, [outcome(d[0], 200)])
    st, _, _ = receipt(st, [outcome(r[0], 200)])
    f = engine.view(st)
    assert f["dispatches"] == [] and f["approvals"] == [] and f["chosenEffect"] == "scale_service"
    assert f == engine.view(st), "final view must be deterministic"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
    print(f"{len(tests)} engine tests passed")
