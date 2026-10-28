import asyncio
import os
import tempfile
import unittest
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock
from commandcore_server.collaboration_approval import Approval, ApprovalLedger, AuthorizationDenied, action_digest
from commandcore_server.collaboration_trusted_preview import preview_owned_request


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.ledger=ApprovalLedger(os.path.join(self.tmp.name,"qa.db"))
        self.text="Only a disposable QA message."
        digest=sha256(self.text.encode()).hexdigest()
        self.ledger.create(Approval("req","owner","gx10","0x4","QA",42,33,"draft",digest,action_digest(device_id="gx10",window_id="0x4",title="QA",process_id=42,process_start=33,draft_id="draft",draft_sha256=digest,input_x=100,input_y=200,send_key="Return"),100,700))
        self.agents=SimpleNamespace(connections={"gx10":object()})
        self.data={"draft_id":"draft","window_id":"0x4","title":"QA","pid":42,"process_start":33,
                   "text":self.text,"input_x":100,"input_y":200,"send_key":"Return","preview_only":True,"delivery_authorized":False}
        self.agents.dispatch=AsyncMock(return_value=SimpleNamespace(status="ok",result=self.data))
    def tearDown(self):
        self.ledger.close();self.tmp.cleanup()
    def run_preview(self,**kwargs):
        return asyncio.run(preview_owned_request(ledger=self.ledger,agents=self.agents,
                          device={"id":"gx10"},owner_subject="owner",request_id="req",now=110,**kwargs))
    def test_preview_matches_owner_and_hash(self):
        out=self.run_preview()
        self.assertEqual(out["text"],self.text)
        self.assertFalse(out["delivery_authorized"])
        self.assertEqual(self.agents.dispatch.await_args.kwargs["tool"],"agents.preview")
    def test_mismatched_text_rejected(self):
        self.data["text"]="Tampered"
        with self.assertRaises(AuthorizationDenied):self.run_preview()
    def test_mismatched_target_rejected(self):
        self.data["pid"]=43
        with self.assertRaises(AuthorizationDenied):self.run_preview()
    def test_modified_coordinates_rejected(self):
        self.data["input_x"]=101
        with self.assertRaises(AuthorizationDenied):self.run_preview()
    def test_modified_send_key_rejected(self):
        self.data["send_key"]="ctrl+Return"
        with self.assertRaises(AuthorizationDenied):self.run_preview()
    def test_offline_rejected_without_dispatch(self):
        self.agents.connections={}
        with self.assertRaises(AuthorizationDenied):self.run_preview()
        self.agents.dispatch.assert_not_awaited()
    def test_not_read_only_rejected(self):
        self.data["delivery_authorized"]=True
        with self.assertRaises(AuthorizationDenied):self.run_preview()
    def test_no_foreign_owner_leak(self):
        with self.assertRaises(AuthorizationDenied):
            asyncio.run(preview_owned_request(ledger=self.ledger,agents=self.agents,
              device={"id":"gx10"},owner_subject="intruder",request_id="req",now=110))
        self.agents.dispatch.assert_not_awaited()

if __name__=="__main__":unittest.main()
