import os,tempfile,time
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock
from fastapi import FastAPI,Request
from fastapi.testclient import TestClient
from commandcore_server.collaboration_approval import Approval,ApprovalLedger,action_digest
from commandcore_server.collaboration_review_routes import install_collaboration_review_routes
from commandcore_server.collaboration_review_challenge import ReviewChallenges

with tempfile.TemporaryDirectory() as d:
    ledger=ApprovalLedger(os.path.join(d,"qa.sqlite"))
    now=int(time.time())
    message="Disposable review-only text"
    hash_=sha256(message.encode()).hexdigest()
    ledger.create(Approval("req","owner","gx10","0x4","QA",42,33,"draft",hash_,action_digest(device_id="gx10",window_id="0x4",title="QA",process_id=42,process_start=33,draft_id="draft",draft_sha256=hash_,input_x=100,input_y=200,send_key="Return"),now,now+600))
    preview={"draft_id":"draft","window_id":"0x4","title":"QA","pid":42,
             "process_start":33,"text":message,"input_x":100,"input_y":200,"send_key":"Return","preview_only":True,"delivery_authorized":False}
    class DB:
        def get_accessible_device(self,subject,id):
            return {"id":"gx10","owner_id":"owner"} if subject=="owner" and id=="gx10" else None
    challenges=ReviewChallenges(os.path.join(d,"challenge.sqlite"))
    class Tools:
        db=DB()
        agents=SimpleNamespace(connections={"gx10":object()},
                               dispatch=AsyncMock(return_value=SimpleNamespace(status="ok",result=preview)))
        def _approval_ledger(self):return ledger
        def _review_challenges(self):return challenges
    def principal(request:Request):
        return SimpleNamespace(auth_kind=request.headers.get("x-test-auth-kind","panel-cookie"),
                               subject=request.headers.get("x-test-owner","owner"))
    app=FastAPI()
    install_collaboration_review_routes(app,Tools(),principal,lambda req:True)
    with TestClient(app) as client:
        def check(headers,expected):
            r=client.get("/api/collaboration/approvals/req/preview",headers=headers)
            assert r.status_code==expected,(r.status_code,r.text)
            return r
        ok=check({"x-test-owner":"owner"},200)
        assert ok.json()["text"]==message and ok.headers["cache-control"]=="no-store"
        page=client.get("/collaboration/review/req",headers={"x-test-owner":"owner"})
        assert page.status_code==200 and message in page.text
        assert "This page cannot authorize delivery." in page.text
        assert "no-store" == page.headers["cache-control"]
        denied_page=client.get("/collaboration/review/req",headers={"x-test-owner":"intruder"})
        assert denied_page.status_code==404
        check({"x-test-owner":"intruder"},404)
        check({"x-test-owner":"owner","x-test-auth-kind":"oauth2"},403)
        assert Tools.agents.dispatch.await_count==2
        challenge=client.post("/api/collaboration/approvals/req/review-challenge",
                              headers={"x-test-owner":"owner","origin":"https://testserver"})
        assert challenge.status_code==200,challenge.text
        assert challenge.json()["delivery_authorized"] is False
        denied=client.post("/api/collaboration/approvals/req/review-challenge",
                           headers={"x-test-owner":"intruder","origin":"https://testserver"})
        assert denied.status_code==404
        bearer=client.post("/api/collaboration/approvals/req/review-challenge",
                           headers={"x-test-auth-kind":"oauth2","origin":"https://testserver"})
        assert bearer.status_code==403
        missing_origin=client.post("/api/collaboration/approvals/req/review-challenge",
                                   headers={"x-test-owner":"owner"})
        assert missing_origin.status_code==403
        preview["text"]="tampered"
        check({"x-test-owner":"owner"},409)
        assert ledger.get(owner_subject="owner",request_id="req").status=="pending"
    challenges.close()
    ledger.close()
print("PREVIEW_HTTP_PASS 5 assertions")
