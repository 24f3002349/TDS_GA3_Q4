"""Replay captured grader incidents (JSON bodies, sensitive object removed) against a server and print each plan.
Usage: python replay_real.py http://127.0.0.1:8000 <dir with incident JSON files>"""
import glob
import json
import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx

BASE, FOLDER = sys.argv[1].rstrip("/"), sys.argv[2]


def drive(path):
    body = json.load(open(path, encoding="utf-8"))
    if "profile" not in body:
        return ""
    body["runId"] = "replay_" + uuid.uuid4().hex[:12]
    body["sensitive"] = {"accessToken": "canary-" + uuid.uuid4().hex, "privateNote": "note-" + uuid.uuid4().hex}
    out = []
    with httpx.Client(timeout=30) as c:
        r = c.post(f"{BASE}/v2/incidents", json=body)
        state = r.json()
        out.append(f"== {body['incident']['service']} {r.status_code} keys={sorted(state)}")
        out.append(f"   cause={state['diagnosis']['rootCause']} evidence={state['diagnosis']['evidence']}")
        n = 0
        while state.get("status") == "waiting" and n < 6:
            n += 1
            for d in state["dispatches"]:
                out.append(f"   {d['phase']:10} {d['toolName']:20} {json.dumps(d['arguments'])} ev={d['evidence']}")
            if state["approvals"]:
                a = state["approvals"][0]
                out.append(f"   approval   {a['toolName']}")
                receipt = {"receiptId": f"r{n}_{uuid.uuid4().hex[:8]}", "approvals": [
                    {"approvalId": a["approvalId"], "decision": "approved", "nonce": str(uuid.uuid4())}]}
            else:
                receipt = {"receiptId": f"r{n}_{uuid.uuid4().hex[:8]}", "outcomes": [
                    {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": 200,
                     "resultClass": "diagnosis_confirmed" if d["phase"] == "diagnostic" else "effect_applied",
                     "nonce": str(uuid.uuid4())} for d in state["dispatches"]]}
            state = c.post(f"{BASE}/v2/incidents/{body['runId']}/receipts", json=receipt).json()
        out.append(f"   final={state.get('status')} chosen={state.get('chosenEffect')} keys={sorted(state)}")
        leak = any(v in json.dumps(state) for v in body["sensitive"].values())
        out.append(f"   sensitive leak: {leak}")
    return "\n".join(out)


files = sorted(f for f in glob.glob(os.path.join(FOLDER, "*.json")) if not os.path.basename(f).startswith("resp"))
with ThreadPoolExecutor(len(files)) as pool:
    for text in pool.map(drive, files):
        print(text)
