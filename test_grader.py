"""Grader-like end-to-end check over captured incident bodies (sensitive object removed; fresh canaries are added).
Usage: python test_grader.py <base-url> <dir with incident JSON files> [--parallel]

Per incident it drives one scenario (plain, 503 retry, timeout, approval) and checks the HTTP contract, replay and
conflict handling, the action/receipt logs and the OTLP trace rules from the assignment."""
import glob
import hashlib
import json
import os
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx

BASE = sys.argv[1].rstrip("/")
FOLDER = sys.argv[2]
PARALLEL = "--parallel" in sys.argv
HEX = re.compile(r"^[0-9a-f]+$")


def attr(span, key):
    for a in span.get("attributes", []):
        if a["key"] == key:
            return next(iter(a["value"].values()))
    return None


def digest(args):
    return hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode()).hexdigest()


def run_one(path, scenario, with_trace):
    errors = []

    def check(cond, msg):
        if not cond:
            errors.append(msg)

    body = json.load(open(path, encoding="utf-8"))
    body["runId"] = "run_" + uuid.uuid4().hex[:22]
    body["publicMarker"] = "PUBLIC_" + uuid.uuid4().hex[:18]
    canaries = {"accessToken": "tok_" + uuid.uuid4().hex, "privateNote": "note_" + uuid.uuid4().hex}
    body["sensitive"] = canaries
    transcript_ids = set(re.findall(r"^\s*\[([^\]\s]+)\]", body["incident"]["transcript"], re.M))
    headers = {}
    tp = None
    if with_trace:
        tp = f"00-{uuid.uuid4().hex}-{uuid.uuid4().hex[:16]}-01"
        headers = {"traceparent": tp, "tracestate": "grader=" + uuid.uuid4().hex[:8]}
    texts = []
    with httpx.Client(timeout=30) as c:
        t0 = time.monotonic()
        r = c.post(f"{BASE}/v2/incidents", json=body, headers=headers)
        elapsed = time.monotonic() - t0
        check(r.status_code == 200, f"POST status {r.status_code}")
        check(r.headers.get("content-type", "").startswith("application/json"), "POST content-type")
        check(elapsed < 18, f"POST took {elapsed:.1f}s")
        check(len(r.content) < 768 * 1024, "POST too large")
        texts.append(r.text)
        first_text, first = r.text, r.json()
        check(sorted(first) == ["approvals", "diagnosis", "dispatches", "runId", "status"], f"waiting keys {sorted(first)}")
        check(first["status"] == "waiting" and first["runId"] == body["runId"], "first status/runId")
        diag = first["diagnosis"]
        check(diag["rootCause"] in body["incident"]["allowedRootCauses"], "rootCause not allowed")
        ev = diag["evidence"]
        check(2 <= len(ev) <= 4 and len(set(ev)) == len(ev) and set(ev) <= transcript_ids, f"diagnosis evidence {ev}")
        check(1 <= len(first["dispatches"]) <= min(3, body["policy"].get("maximumDiagnostics", 3)), "diagnostic count")
        catalog = {t["name"]: t for t in body["toolCatalog"]}
        issued = []
        for d in first["dispatches"]:
            check(d["phase"] == "diagnostic" and d["toolName"] not in body["policy"]["effectTools"], "diagnostic phase")
            check(set((catalog[d["toolName"]].get("inputSchema") or {}).get("required", [])) <= set(d["arguments"]),
                  f"missing required args for {d['toolName']}")
        all_dispatches = []

        def seen(ds):
            for d in ds:
                all_dispatches.append(d)
                check(len(d["actionId"]) >= 8 and len(d["callId"]) >= 8, "id length")
                check(d["evidence"] and len(set(d["evidence"])) == len(d["evidence"]) and set(d["evidence"]) <= set(ev),
                      "dispatch evidence")
                m = re.fullmatch(r"00-([0-9a-f]{32})-([0-9a-f]{16})-01", d["traceparent"])
                check(bool(m), "traceparent format")
                if tp and m:
                    check(m.group(1) == tp.split("-")[1], "trace not continued")
                check((d.get("tracestate") == headers.get("tracestate")) if tp else ("tracestate" not in d),
                      "tracestate handling")

        seen(first["dispatches"])
        logical = {d["actionId"]: d["callId"] for d in first["dispatches"]}
        check(len(set(logical.values())) == len(logical), "callIds unique")
        state, receipts, n = first, [], 0
        approval_seen = None
        while state["status"] == "waiting" and n < 8:
            n += 1
            rid = f"rcpt_{n}_{uuid.uuid4().hex[:10]}"
            if state["approvals"]:
                check(len(state["approvals"]) == 1 and not state["dispatches"], "approval request shape")
                a = state["approvals"][0]
                approval_seen = a
                receipt = {"receiptId": rid, "approvals": [{"approvalId": a["approvalId"], "decision": "approved",
                                                            "nonce": str(uuid.uuid4())}]}
            else:
                outs = []
                for d in state["dispatches"]:
                    status, extra = 200, {"resultClass": "diagnosis_confirmed" if d["phase"] == "diagnostic"
                                          else "effect_applied"}
                    if scenario == "retry" and d["attempt"] == 1 and d is state["dispatches"][0]:
                        status, extra = 503, {"resultClass": "unavailable"}
                    if scenario == "timeout" and d["phase"] == "diagnostic" and d is state["dispatches"][-1]:
                        status, extra = 0, {"errorType": "timeout"}
                    outs.append({"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"],
                                 "status": status, **extra, "nonce": str(uuid.uuid4())})
                receipt = {"receiptId": rid, "outcomes": outs}
            rr = c.post(f"{BASE}/v2/incidents/{body['runId']}/receipts", json=receipt)
            check(rr.status_code == 200, f"receipt status {rr.status_code} {rr.text[:120]}")
            if rr.status_code != 200:
                break
            texts.append(rr.text)
            receipts.append((receipt, rr.text))
            state = rr.json()
            retry = [d for d in state["dispatches"] if d["attempt"] > 1]
            if retry:
                check(not state["approvals"], "retry response contains approval")
                for d in retry:
                    check(logical.get(d["actionId"]) == d["callId"], "retry kept ids")
            for d in state["dispatches"]:
                if d["phase"] == "effect" and d["toolName"] in body["policy"]["approvalRequiredFor"]:
                    check(approval_seen and d.get("approvalId") == approval_seen["approvalId"]
                          and d.get("approvalNonce") and d["actionId"] == approval_seen["actionId"],
                          "approved effect fields")
                    check(approval_seen and approval_seen["argumentsDigest"] == digest(d["arguments"]),
                          "argumentsDigest")
                logical.setdefault(d["actionId"], d["callId"])
            seen(state["dispatches"])

        final = c.get(f"{BASE}/v2/incidents/{body['runId']}").json()
        check(final == state, "GET differs from last response")
        check(final["status"] in ("completed", "failed"), f"not terminal: {final['status']}")
        check(final["dispatches"] == [] and final["approvals"] == [], "final has pending work")
        check(final["actionLog"] == all_dispatches, "actionLog != dispatches issued")
        effects = [d for d in final["actionLog"] if d["phase"] == "effect"]
        if scenario == "timeout":
            check(final["status"] == "failed" and not effects and final["suppressed"], "timeout must suppress effect")
        else:
            check(final["status"] == "completed" and len({d["actionId"] for d in effects}) == 1, "exactly one effect")
            check(final["chosenEffect"] == effects[0]["toolName"] if effects else False, "chosenEffect")
        outcome_count = sum(len(rc.get("outcomes", [])) + len(rc.get("approvals", [])) for rc, _ in receipts)
        check(len(final["receiptLog"]) == outcome_count, "receiptLog incomplete")
        for e in final["receiptLog"]:
            check("receiptId" in e and "nonce" in e, "receiptLog entry shape")

        # replay, conflicts, invalid input
        r2 = c.post(f"{BASE}/v2/incidents", json=body, headers=headers)
        check(r2.status_code == 200 and r2.text == first_text, "POST replay not identical")
        if receipts:
            rc, txt = receipts[0]
            r3 = c.post(f"{BASE}/v2/incidents/{body['runId']}/receipts", json=rc)
            check(r3.status_code == 200 and r3.text == txt, "receipt replay not identical")
            bad = json.loads(json.dumps(rc))
            (bad.get("outcomes") or bad.get("approvals"))[0]["nonce"] = str(uuid.uuid4())
            check(c.post(f"{BASE}/v2/incidents/{body['runId']}/receipts", json=bad).status_code == 409,
                  "changed receipt not 409")
        changed = json.loads(json.dumps(body))
        changed["incident"]["title"] += " changed"
        check(c.post(f"{BASE}/v2/incidents", json=changed).status_code == 409, "changed run not 409")
        invalid = json.loads(json.dumps(body))
        invalid["runId"] += "_invalid"
        invalid["profile"] = "ga5-incident-agent/v1"
        rv = c.post(f"{BASE}/v2/incidents", json=invalid)
        check(rv.status_code in (400, 422), f"invalid profile -> {rv.status_code}")
        check(c.get(f"{BASE}/v2/incidents/{invalid['runId']}").status_code == 404, "invalid request created a run")
        stray = {"receiptId": "rcpt_stray_" + uuid.uuid4().hex[:8], "outcomes": [
            {"actionId": "act_unknown01", "callId": "call_unknown01", "attempt": 1, "status": 200, "nonce": "n"}]}
        check(c.post(f"{BASE}/v2/incidents/{body['runId']}/receipts", json=stray).status_code in (400, 409, 422),
              "stray outcome accepted")
        after = c.get(f"{BASE}/v2/incidents/{body['runId']}").json()
        check(after == final, "state changed by replay/conflict probes")
        texts += [r2.text, rv.text]

    # redaction across every response
    blob = "\n".join(texts) + json.dumps(final)
    for v in canaries.values():
        check(v not in blob, "sensitive value leaked")
    check(body["incident"]["transcript"][:60] not in blob, "transcript exported")

    # OTLP trace rules
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    ids = {s["spanId"]: s for s in spans}
    check(len(ids) == len(spans), "duplicate span ids")
    names = [s["name"] for s in spans]
    server = [s for s in spans if s["kind"] == 2]
    check(len(server) == 1 and server[0]["name"] == "POST /v2/incidents", "SERVER span")
    tid = server[0]["traceId"]
    check(all(s["traceId"] == tid for s in spans), "mixed trace ids")
    check(bool(HEX.match(tid)) and int(tid, 16) != 0 and all(HEX.match(s["spanId"]) and int(s["spanId"], 16)
                                                             for s in spans), "ids not lowercase hex")
    if tp:
        check(tid == tp.split("-")[1] and server[0].get("parentSpanId") == tp.split("-")[2], "server not continued")
    agent = [s for s in spans if s["name"] == f"invoke_agent {body['agentName']}"]
    check(len(agent) == 1 and agent[0]["kind"] == 1 and agent[0].get("parentSpanId") == server[0]["spanId"], "agent")
    chat = [s for s in spans if s["name"] == "chat incident-plan"]
    check(len(chat) == 1 and chat[0]["kind"] == 3 and attr(chat[0], "gen_ai.operation.name") == "chat"
          and attr(chat[0], "gen_ai.request.model"), "chat span")
    for s in spans:
        check(attr(s, "ga5.run.id") == body["runId"] and attr(s, "ga5.public.marker") == body["publicMarker"],
              f"common attrs on {s['name']}")
        check(s is server[0] or s.get("parentSpanId") in ids, f"orphan {s['name']}")
        keys = {a["key"] for a in s["attributes"]}
        check(not keys & {"gen_ai.tool.call.arguments", "gen_ai.tool.call.result"}, "tool args exported")
    executed = {}
    for d in final["actionLog"]:
        executed.setdefault(d["actionId"], d)
    tools = [s for s in spans if s["name"].startswith("execute_tool ")]
    check(len(tools) == len(executed), f"execute_tool spans {len(tools)} != actions {len(executed)}")
    for s in tools:
        a = executed.get(attr(s, "ga5.action.id"))
        check(a and s["kind"] == 1 and s["parentSpanId"] == agent[0]["spanId"] and attr(s, "gen_ai.tool.name") ==
              a["toolName"] and attr(s, "gen_ai.tool.call.id") == a["callId"]
              and attr(s, "gen_ai.operation.name") == "execute_tool", "execute_tool attrs")
    clients = [s for s in spans if s["name"].startswith("POST tool/")]
    check(len(clients) == len(final["actionLog"]), "one CLIENT span per attempt")
    for d in final["actionLog"]:
        s = ids.get(d["traceparent"].split("-")[2])
        check(s is not None and s["kind"] == 3 and s["name"] == f"POST tool/{d['toolName']}", "client span id")
        if not s:
            continue
        check(ids[s["parentSpanId"]]["name"] == f"execute_tool {d['toolName']}", "client parent")
        r = next((x for x in final["receiptLog"] if x.get("actionId") == d["actionId"] and x["attempt"] == d["attempt"]),
                 None)
        check(r is not None, "receipt for attempt")
        if not r:
            continue
        check(int(attr(s, "ga5.attempt")) == d["attempt"] and int(attr(s, "http.request.resend_count")) == d["attempt"] - 1,
              "attempt/resend attrs")
        check(attr(s, "ga5.receipt.id") == r["receiptId"] and attr(s, "ga5.receipt.nonce") == r["nonce"]
              and attr(s, "http.request.method") == "POST" and attr(s, "ga5.action.id") == d["actionId"], "receipt attrs")
        if r["status"] == 503:
            check(s.get("status", {}).get("code") == 2 and attr(s, "error.type") == "503", "503 span")
        elif r["status"] == 0:
            check(s.get("status", {}).get("code") == 2 and attr(s, "error.type") == "timeout", "timeout span")
        else:
            check(s.get("status", {}).get("code") != 2 and attr(s, "error.type") is None, "success span")
    diag_spans = [s for s in tools if executed[attr(s, "ga5.action.id")]["phase"] == "diagnostic"]
    join = [s for s in spans if s["name"] == "incident.join"]
    if len(diag_spans) > 1:
        check(len(join) == 1 and join[0]["parentSpanId"] == agent[0]["spanId"]
              and {l["spanId"] for l in join[0].get("links", [])} == {s["spanId"] for s in diag_spans}, "join span")
    else:
        check(not join, "unexpected join")
    gate = [s for s in spans if s["name"] == "approval_gate"]
    if approval_seen:
        apr = next(x for x in final["receiptLog"] if x.get("approvalId"))
        check(len(gate) == 1 and attr(gate[0], "ga5.approval.id") == apr["approvalId"]
              and apr["nonce"] in {a["value"].get("stringValue") for a in gate[0]["attributes"]}, "approval_gate")
    else:
        check(not gate, "unexpected approval_gate")
    plan = [(d["toolName"], d["arguments"]) for d in final["actionLog"] if d["attempt"] == 1]
    return os.path.basename(path), scenario, diag["rootCause"], plan, final["status"], elapsed, errors


def main():
    files = sorted(f for f in glob.glob(os.path.join(FOLDER, "*.json"))
                   if not os.path.basename(f).startswith(("resp", "ref_", "final_")))
    jobs = []
    for i, f in enumerate(files):
        text = open(f, encoding="utf-8").read()
        scenario = ("timeout" if "secret" in text and "read_runbook" in text and "runbook is required" in text
                    else "retry" if i % 3 == 0 else "plain")
        jobs.append((f, scenario, i == 0))
    runner = (lambda j: run_one(*j))
    if PARALLEL:
        with ThreadPoolExecutor(len(jobs)) as pool:
            results = list(pool.map(runner, jobs))
    else:
        results = [runner(j) for j in jobs]
    failed = 0
    for name, scenario, cause, plan, status, elapsed, errors in results:
        failed += bool(errors)
        print(f"{'PASS' if not errors else 'FAIL'} {name:22} {scenario:7} {cause:31} {status:9} {elapsed:4.1f}s")
        for t, a in plan:
            print(f"       {t:20} {json.dumps(a)}")
        for e in errors:
            print("       !", e)
    print(f"\n{len(results) - failed}/{len(results)} incidents passed every check")


if __name__ == "__main__":
    main()
