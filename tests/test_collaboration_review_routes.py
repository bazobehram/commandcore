import os, tempfile, time
from types import SimpleNamespace
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from commandcore_server.collaboration_approval import Approval, ApprovalLedger
from commandcore_server.collaboration_review_routes import install_collaboration_review_routes

with tempfile.TemporaryDirectory() as d:
    ledger = ApprovalLedger(os.path.join(d,"qa.sqlite"))
    now=int(time.time())
    ledger.create(Approval("req-A","owner-A","gx10","0x1","Fixture",23,42,"draft-A","a"*64,"b"*64,now,now+600))
    ledger.create(Approval("req/special?", "owner-A", "gx10", "0x3", "Unsafe <script>", 25, 44, "draft-C", "a"*64, "b"*64, now, now+600))
    ledger.create(Approval("req-B","owner-B","gx10","0x2","Other",24,43,"draft-B","a"*64,"b"*64,now,now+600))
    class Tools:
        def _approval_ledger(self):return ledger
    def principal(request:Request):
        return SimpleNamespace(auth_kind=request.headers.get("x-test-auth-kind","panel-cookie"),subject=request.headers.get("x-test-owner","owner-A"))
    app=FastAPI()
    install_collaboration_review_routes(app,Tools(),principal,lambda req:req.headers.get("origin")=="https://testserver")
    with TestClient(app) as client:
        headers={"origin":"https://testserver","x-test-owner":"owner-A"}
        def check(method,path,expected,h=headers):
            res=client.request(method,path,headers=h);assert res.status_code==expected,(path,res.status_code,res.text);return res
        landing=check("GET","/collaboration/review",200)
        assert 'id="enroll-passkey"' in landing.text
        assert 'id="enrollment-status"' in landing.text
        assert '<script src="/collaboration/webauthn-enroll.js" defer></script>' in landing.text
        assert landing.headers["content-security-policy"].find("script-src 'self'")>=0
        # A cross-site form must not be able to reject a pending request.
        denied_path="/api/collaboration/approvals/req-A/deny"
        for blocked_headers in (
            {"origin":"https://evil.example","x-test-owner":"owner-A"},
            {"x-test-owner":"owner-A","sec-fetch-site":"cross-site"},
            {"x-test-owner":"owner-A","x-test-auth-kind":"oauth-bearer",
             "origin":"https://testserver"},
        ):
            blocked=client.post(denied_path,headers=blocked_headers)
            assert blocked.status_code==403,(blocked.status_code,blocked.text)
            assert ledger.get(owner_subject="owner-A",request_id="req-A").status=="pending"
        # Registration endpoints require explicit server config and private panel.
        check("POST","/api/collaboration/webauthn/register/begin",503)
        check("POST","/api/collaboration/webauthn/register/finish",503)
        check("POST","/api/collaboration/webauthn/register/begin",403,
              {**headers,"x-test-auth-kind":"oauth-bearer"})
        check("POST","/api/collaboration/webauthn/register/finish",403,
              {**headers,"origin":"https://evil.test"})
        os.environ["COMMANDCORE_WEBAUTHN_RP_ID"]="testserver"
        os.environ["COMMANDCORE_WEBAUTHN_ORIGIN"]="https://testserver"
        try:
            check("POST","/api/collaboration/webauthn/register/finish",400)
            check("POST","/api/collaboration/webauthn/register/finish",400)
        finally:
            os.environ.pop("COMMANDCORE_WEBAUTHN_RP_ID",None)
            os.environ.pop("COMMANDCORE_WEBAUTHN_ORIGIN",None)
        script=check("GET","/collaboration/webauthn-enroll.js",200)
        assert "navigator.credentials.create" in script.text
        assert "application/javascript" in script.headers["content-type"]
        assert script.headers["cache-control"]=="no-store"
        check("GET","/collaboration/webauthn-enroll.js",403,
              {"x-test-auth-kind":"oauth-bearer"})
        check("POST","/api/collaboration/approvals/req-A/verify-webauthn",503)
        os.environ["COMMANDCORE_WEBAUTHN_RP_ID"]="testserver"
        os.environ["COMMANDCORE_WEBAUTHN_ORIGIN"]="https://testserver"
        try:
            check("POST","/api/collaboration/approvals/req-A/verify-webauthn",400)
            check("POST","/api/collaboration/approvals/req-A/verify-webauthn",403,
                  {**headers,"x-test-auth-kind":"oauth-bearer"})
        finally:
            os.environ.pop("COMMANDCORE_WEBAUTHN_RP_ID",None)
            os.environ.pop("COMMANDCORE_WEBAUTHN_ORIGIN",None)
        # An authenticated HTTP route may report verified evidence, never
        # change the approval ledger or dispatch any message.
        import sys,types,base64
        from unittest.mock import patch,AsyncMock
        module=types.ModuleType("commandcore_server.collaboration_webauthn_review")
        module.verify_review_assertion=AsyncMock(return_value={
          "request_id":"req-A","credential_verified":True,"counter":7,
          "delivery_authorized":False})
        class DummyDB:
            def get_accessible_device(self,owner,device_id):
                return {"id":device_id,"owner_id":owner}
        class RouteTools:
            db=DummyDB()
            agents=object()
            def _approval_ledger(self):return ledger
            def _review_challenges(self):return object()
            def _webauthn_credentials(self):return object()
        # Existing routes captured Tools(); build an independent HTTP fixture
        # with full owner/device checks and a substituted verifier only.
        app_verify=FastAPI()
        install_collaboration_review_routes(app_verify,RouteTools(),principal,
           lambda req:req.headers.get("origin")=="https://testserver")
        os.environ["COMMANDCORE_WEBAUTHN_RP_ID"]="testserver"
        os.environ["COMMANDCORE_WEBAUTHN_ORIGIN"]="https://testserver"
        encoded=base64.urlsafe_b64encode(b"x"*37).rstrip(b"=").decode()
        payload={"challenge":"t"*43,"credentialId":"cred",
                 "authenticatorData":encoded,"clientDataJSON":encoded,"signature":encoded}
        try:
            with patch.dict(sys.modules,{"commandcore_server.collaboration_webauthn_review":module}):
                with TestClient(app_verify) as verify_client:
                    url="/api/collaboration/approvals/req-A/verify-webauthn"
                    valid=verify_client.post(url,json=payload,headers=headers)
                    assert valid.status_code==200,(valid.status_code,valid.text)
                    assert valid.json()["credential_verified"] is True
                    assert valid.json()["delivery_authorized"] is False
                    forbidden=verify_client.post(url,json=payload,
                        headers={**headers,"x-test-owner":"owner-B"})
                    assert forbidden.status_code==404
                    for field in ("credentialId","authenticatorData","clientDataJSON","signature"):
                        tampered=dict(payload)
                        tampered[field]=encoded+"=" if field!="credentialId" else "AQ=="
                        bad_encoding=verify_client.post(url,json=tampered,headers=headers)
                        assert bad_encoding.status_code==400,(field,bad_encoding.status_code,bad_encoding.text)
                    forged=verify_client.post(url,json=payload,
                        headers={**headers,"x-test-auth-kind":"oauth-bearer"})
                    assert forged.status_code==403
            assert module.verify_review_assertion.await_count==1
            assert ledger.get(owner_subject="owner-A",request_id="req-A").status=="pending"
        finally:
            os.environ.pop("COMMANDCORE_WEBAUTHN_RP_ID",None)
            os.environ.pop("COMMANDCORE_WEBAUTHN_ORIGIN",None)
        os.environ["COMMANDCORE_WEBAUTHN_RP_ID"]="testserver"
        os.environ["COMMANDCORE_WEBAUTHN_ORIGIN"]="https://testserver"
        try:
            for endpoint in ("/api/collaboration/webauthn/register/finish",
                             "/api/collaboration/approvals/req-A/verify-webauthn"):
                bad=client.post(endpoint,data=b"{}",headers={**headers,"content-length":"-1"})
                assert bad.status_code==400,(endpoint,bad.status_code,bad.text)
        finally:
            os.environ.pop("COMMANDCORE_WEBAUTHN_RP_ID",None)
            os.environ.pop("COMMANDCORE_WEBAUTHN_ORIGIN",None)
        page=check("GET","/collaboration/review",200)
        assert 'Pending collaboration requests' in page.text
        assert 'req-B' not in page.text
        assert 'approve' not in page.text.lower().replace('approved or delivered','')
        assert "form-action 'self'" in page.headers["content-security-policy"]
        assert "req%2Fspecial%3F/deny" in page.text
        assert "<script>" not in page.text
        assert 'action="/api/collaboration/approvals/req-A/deny"' in page.text
        assert page.headers["cache-control"]=="no-store"
        listing=check("GET","/api/collaboration/approvals",200).json()["requests"]
        check("GET","/api/collaboration/approvals",200,{"x-test-owner":"owner-A"})
        check("GET","/api/collaboration/approvals",403,{"x-test-owner":"owner-A","x-test-auth-kind":"oauth-bearer"})
        assert {i["request_id"] for i in listing}=={"req-A","req/special?"}
        check("POST","/api/collaboration/approvals/req-B/deny",400)
        check("POST","/api/collaboration/approvals/req-A/deny",403,{"origin":"https://evil.test"})
        check("POST","/api/collaboration/approvals/req-A/deny",403,{"x-test-owner":"owner-A"})
        check("POST","/api/collaboration/approvals/req-A/deny",403,{**headers,"x-test-auth-kind":"oauth-bearer"})
        assert check("POST","/api/collaboration/approvals/req-A/deny",200).json()["status"]=="denied"
        check("POST","/api/collaboration/approvals/req-A/deny",400)
        check("POST","/api/collaboration/approvals/req-A/approve",404)
        assert ledger.get(owner_subject="owner-B",request_id="req-B").status=="pending"
        assert check("GET","/api/collaboration/approvals",200).headers["cache-control"]=="no-store"
        assert all(len(x["draft_sha256"])==64 and len(x["action_sha256"])==64 for x in listing)
        assert all(x["approval_ready"] is False and x["delivery_authorized"] is False for x in listing)
        print("HTTP_ROUTE_ACCEPTANCE_PASS 18 checks")
    ledger.close()
