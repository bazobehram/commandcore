import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.browser_gateway import BrowserGateway, OwnedSession
from commandcore_server.models import Principal
from commandcore_server.tools import ToolError, ToolService


class TakeoverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        class DB:
            def add_audit(self, **kwargs):
                return 1
        self.gateway = BrowserGateway(base_url="http://steel:3000",
                                      cdp_url="ws://steel:3000",
                                      allow_hosts=("example.com",))
        self.principal = Principal(subject="owner", issuer="https://idp.test",
                                   client_id="app", auth_kind="oauth2",
                                   scopes=(READ_SCOPE, STANDARD_SCOPE))
        self.service = ToolService(DB(), None, 300, browser=self.gateway)
        self.owner = (self.principal.issuer, self.principal.subject, self.principal.client_id)
        self.old = OwnedSession("a" * 36)
        self.gateway.sessions[self.owner] = self.old
        self.service._browser_conversation_leases[self.owner] = self.service.live_activity.session_tag("chat-A")
        self.args = {"expected_session_id": self.old.id, "confirmed": True,
                     "url": "https://example.com/"}
        self.gateway.call = AsyncMock(return_value={"session_id": "b" * 36})

    async def deny(self, code, args=None, principal=None):
        with self.assertRaises(ToolError) as caught:
            await self.service.call(principal or self.principal, "browser.takeover",
                                    args or self.args, host_session="chat-B")
        self.assertEqual(caught.exception.code, code)
        self.gateway.call.assert_not_awaited()

    async def test_confirmation_required(self):
        await self.deny("browser_takeover_confirmation_required",
                        {**self.args, "confirmed": False})

    async def test_stale_session_denied(self):
        await self.deny("browser_takeover_stale_session",
                        {**self.args, "expected_session_id": "c" * 36})

    async def test_private_handoff_denied(self):
        self.old.paused_for_human = True
        await self.deny("browser_takeover_busy")

    async def test_inflight_denied(self):
        self.old.action_running = True
        await self.deny("browser_takeover_busy")

    async def test_other_client_denied(self):
        other = Principal(subject="owner", issuer="https://idp.test",
                          client_id="another-app", auth_kind="oauth2",
                          scopes=(READ_SCOPE, STANDARD_SCOPE))
        await self.deny("browser_takeover_stale_session", principal=other)

    async def test_successful_transfer_closes_before_open(self):
        calls = []
        async def invoke(**kwargs):
            calls.append(kwargs["name"])
            return ({"closed": True} if kwargs["name"] == "browser.close"
                    else {"session_id": "b" * 36})
        self.gateway.call.side_effect = invoke
        with (patch.object(self.service, "_browser_lease_delete"),
              patch.object(self.service, "_browser_lease_save")):
            prepared = await self.service.call(self.principal, "browser.takeover.prepare",
                                               {}, host_session="chat-B")
            result = await self.service.call(self.principal, "browser.takeover",
                                             {**self.args, "challenge": prepared["challenge"]},
                                             host_session="chat-B")
        self.assertTrue(result["taken_over"])
        self.assertEqual(calls, ["browser.close", "browser.open"])
        self.assertEqual(self.service._browser_conversation_leases[self.owner],
                         self.service.live_activity.session_tag("chat-B"))


    async def test_challenge_required(self):
        await self.deny("browser_takeover_challenge_invalid")

    async def test_challenge_belongs_to_conversation(self):
        prepared = await self.service.call(self.principal, "browser.takeover.prepare",
                                           {}, host_session="chat-C")
        with self.assertRaises(ToolError) as caught:
            await self.service.call(self.principal, "browser.takeover",
                                    {**self.args, "challenge": prepared["challenge"]},
                                    host_session="chat-B")
        self.assertEqual(caught.exception.code, "browser_takeover_challenge_invalid")
        self.gateway.call.assert_not_awaited()

    async def test_challenge_expires(self):
        prepared = await self.service.call(self.principal, "browser.takeover.prepare",
                                           {}, host_session="chat-B")
        self.service._browser_takeover_challenges[self.owner]["expires"] = 0
        with self.assertRaises(ToolError) as caught:
            await self.service.call(self.principal, "browser.takeover",
                                    {**self.args, "challenge": prepared["challenge"]},
                                    host_session="chat-B")
        self.assertEqual(caught.exception.code, "browser_takeover_challenge_invalid")
        self.gateway.call.assert_not_awaited()

    async def test_replay_rejected(self):
        async def invoke(**kwargs):
            return {"closed": True} if kwargs["name"] == "browser.close" else {"session_id": "b" * 36}
        self.gateway.call.side_effect = invoke
        prepared = await self.service.call(self.principal, "browser.takeover.prepare",
                                           {}, host_session="chat-B")
        with (patch.object(self.service, "_browser_lease_delete"),
              patch.object(self.service, "_browser_lease_save")):
            args = {**self.args, "challenge": prepared["challenge"]}
            result = await self.service.call(self.principal, "browser.takeover",
                                             args, host_session="chat-B")
            self.assertTrue(result["taken_over"])
            with self.assertRaises(ToolError):
                await self.service.call(self.principal, "browser.takeover",
                                        args, host_session="chat-B")

    async def test_second_conversation_supersedes_first_challenge(self):
        first = await self.service.call(self.principal, "browser.takeover.prepare",
                                        {}, host_session="chat-B")
        second = await self.service.call(self.principal, "browser.takeover.prepare",
                                         {}, host_session="chat-C")
        self.assertNotEqual(first["challenge"], second["challenge"])
        with self.assertRaises(ToolError) as caught:
            await self.service.call(self.principal, "browser.takeover",
                                    {**self.args, "challenge": first["challenge"]},
                                    host_session="chat-B")
        self.assertEqual(caught.exception.code, "browser_takeover_challenge_invalid")
        self.gateway.call.assert_not_awaited()

    async def test_prepare_requires_matching_owner_and_valid_conversation(self):
        with self.assertRaises(ToolError) as caught:
            await self.service.call(self.principal, "browser.takeover.prepare", {},
                                    host_session=None)
        self.assertEqual(caught.exception.code, "browser_conversation_required")
        other = Principal(subject="other", issuer=self.principal.issuer,
                          client_id=self.principal.client_id, auth_kind="oauth2",
                          scopes=(READ_SCOPE, STANDARD_SCOPE))
        with self.assertRaises(ToolError) as caught:
            await self.service.call(other, "browser.takeover.prepare", {},
                                    host_session="chat-B")
        self.assertEqual(caught.exception.code, "browser_takeover_stale_session")

    async def test_restart_requires_new_challenge(self):
        prepared = await self.service.call(self.principal, "browser.takeover.prepare",
                                           {}, host_session="chat-B")
        self.service._browser_takeover_challenges.clear()
        await self.deny("browser_takeover_challenge_invalid",
                        {**self.args, "challenge": prepared["challenge"]})


    async def test_previous_conversation_cannot_act_during_or_after_transfer(self):
        prepared = await self.service.call(self.principal, "browser.takeover.prepare",
                                           {}, host_session="chat-B")
        entered = asyncio.Event()
        allow_close = asyncio.Event()
        async def invoke(**kwargs):
            if kwargs["name"] == "browser.close":
                entered.set()
                await allow_close.wait()
                return {"closed": True}
            return {"session_id": "b" * 36}
        self.gateway.call.side_effect = invoke
        with (patch.object(self.service, "_browser_lease_delete"),
              patch.object(self.service, "_browser_lease_save")):
            switching = asyncio.create_task(
                self.service.call(self.principal, "browser.takeover",
                                  {**self.args, "challenge": prepared["challenge"]},
                                  host_session="chat-B")
            )
            await asyncio.wait_for(entered.wait(), 2)
            previous = asyncio.create_task(
                self.service.call(self.principal, "browser.frame", {},
                                  host_session="chat-A")
            )
            await asyncio.sleep(0)
            self.assertFalse(previous.done())
            allow_close.set()
            self.assertTrue((await switching)["taken_over"])
            with self.assertRaises(ToolError) as caught:
                await previous
            self.assertEqual(caught.exception.code, "browser_conversation_in_use")
