"""Linux-only, isolated-network canary: real packet drops and same-process auth.

Run only inside a disposable container/network namespace with NET_ADMIN.
The LD_PRELOAD resolver fixture and iptables changes are private to that
container. Never run these fault injections in a production host namespace.
"""

import asyncio
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from websockets.asyncio.server import serve


RESOLVER = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
int getaddrinfo(const char *name,const char *service,const struct addrinfo *hints,struct addrinfo **result) {
 int (*real)(const char*,const char*,const struct addrinfo*,struct addrinfo**)=dlsym(RTLD_NEXT,"getaddrinfo");
 if (!name || strcmp(name,"commandcore-dual-stack.test")) return real(name,service,hints,result);
 struct addrinfo h={0}; if(hints) h=*hints; h.ai_flags &= ~AI_ADDRCONFIG;
 struct addrinfo *v6=NULL,*v4=NULL; h.ai_family=AF_INET6;
 int e6=real("::1",service,&h,&v6); h.ai_family=AF_INET;
 int e4=real("127.0.0.1",service,&h,&v4);
 if(e6 || e4) {if(v6)freeaddrinfo(v6);if(v4)freeaddrinfo(v4);return EAI_FAIL;}
 int first4=getenv("CANARY_FIRST_IPV4")!=NULL;
 struct addrinfo *first=first4?v4:v6,*second=first4?v6:v4,*tail=first;
 while(tail->ai_next)tail=tail->ai_next;tail->ai_next=second;*result=first;return 0;
}
"""


async def main():
    if not Path("/run/commandcore-disposable-network").is_file():
        raise RuntimeError(
            "isolated-network marker required; refusing host fault injection"
        )
    root_source = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="commandcore-dual-stack-") as temp:
        root = Path(temp)
        (root / "resolver.c").write_text(RESOLVER)
        subprocess.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-o",
                str(root / "resolver.so"),
                str(root / "resolver.c"),
                "-ldl",
            ],
            check=True,
        )
        key = Ed25519PrivateKey.generate()
        private = base64.b64encode(
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode()
        public = base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()
        state = {
            "device_id": str(uuid.uuid4()),
            "device_token": secrets.token_urlsafe(32),
            "private_key_b64": private,
            "public_key_b64": public,
            "control_url": "http://127.0.0.1",
            "display_name": "disposable-dual-stack",
            "key_generation": 1,
            "state_version": 2,
        }
        state_path = root / "state/agent.json"
        state_path.parent.mkdir(mode=0o700)
        policy = root / "policy.json"
        policy.write_text(json.dumps({"configured_max_permission_profile": "STANDARD"}))
        peers = []
        connected = asyncio.Queue()

        async def handler(ws):
            assert ws.request.path == "/agent"
            assert ws.request.headers["Host"].startswith("commandcore-dual-stack.test:")
            assert (
                ws.request.headers["Authorization"]
                == f"Device {state['device_id']}:{state['device_token']}"
            )
            nonce = secrets.token_urlsafe(24)
            await ws.send(
                json.dumps(
                    {"type": "challenge", "protocol_version": "1", "nonce": nonce}
                )
            )
            hello = json.loads(await asyncio.wait_for(ws.recv(), 10))
            assert hello["device_id"] == state["device_id"]
            key.public_key().verify(
                base64.b64decode(hello["signature"]),
                f"commandcore-agent-auth-v1\n{state['device_id']}\n{nonce}".encode(),
            )
            await ws.send(json.dumps({"type": "hello.ack", "key_generation": 1}))
            peers.append(ws)
            await connected.put(ws)
            try:
                async for raw in ws:
                    if json.loads(raw)["type"] == "heartbeat":
                        await ws.send(json.dumps({"type": "heartbeat.ack"}))
            except Exception:
                pass

        async with serve(handler, "127.0.0.1", 0) as v4:
            port = v4.sockets[0].getsockname()[1]
            async with serve(handler, "::1", port):
                state["agent_url"] = f"ws://commandcore-dual-stack.test:{port}/agent"
                state_path.write_text(json.dumps(state))
                state_path.chmod(0o600)
                identity_before = state_path.read_bytes()
                for implementation in ["python", "rust"]:
                    for preferred in ["ipv6", "ipv4"]:
                        env = {
                            **os.environ,
                            "PYTHONPATH": str(root_source / "agent"),
                            "LD_PRELOAD": str(root / "resolver.so"),
                            "COMMANDCORE_AGENT_POLICY": str(policy),
                            "COMMANDCORE_AGENT_HEALTH_FILE": str(root / "health.json"),
                        }
                        env.pop("RES_OPTIONS", None)
                        if preferred == "ipv4":
                            env["CANARY_FIRST_IPV4"] = "1"
                        else:
                            env.pop("CANARY_FIRST_IPV4", None)
                        binary = os.environ["COMMANDCORE_RUST_AGENT_BIN"]
                        python_binary = os.environ.get("COMMANDCORE_PYTHON_AGENT_BIN")
                        python_command = (
                            [sys.executable, python_binary]
                            if python_binary
                            else [sys.executable, "-m", "commandcore_agent.cli"]
                        )
                        command = (
                            python_command if implementation == "python" else [binary]
                        ) + ["run", "--state", str(state_path)]
                        family = "ip6tables" if preferred == "ipv6" else "iptables"
                        destination = "::1" if preferred == "ipv6" else "127.0.0.1"
                        rule = [
                            "OUTPUT",
                            "-p",
                            "tcp",
                            "-d",
                            destination,
                            "--dport",
                            str(port),
                            "-j",
                            "DROP",
                        ]
                        subprocess.run([family, "-A", *rule], check=True)
                        log_path = root / f"{implementation}-{preferred}.log"
                        with log_path.open("w+") as log:
                            process = subprocess.Popen(
                                command, env=env, stdout=log, stderr=log
                            )
                            try:
                                first = await asyncio.wait_for(connected.get(), 10)
                                assert process.poll() is None
                                pid = process.pid
                                # Lose the established connection while preferred family
                                # stays blackholed. The SAME process must authenticate again.
                                await first.close(
                                    code=1012, reason="disposable reconnect test"
                                )
                                second = await asyncio.wait_for(connected.get(), 10)
                                assert (
                                    second is not first
                                    and process.poll() is None
                                    and process.pid == pid
                                )
                                assert state_path.read_bytes() == identity_before
                                print(
                                    json.dumps(
                                        {
                                            "implementation": implementation,
                                            "scenario": f"{preferred}-blackhole-and-same-process-reconnect",
                                            "status": "PASS",
                                            "pid": pid,
                                            "identity_unchanged": True,
                                        }
                                    ),
                                    flush=True,
                                )
                                await second.close()
                            finally:
                                process.terminate()
                                try:
                                    process.wait(5)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait(5)
                                subprocess.run([family, "-D", *rule], check=True)
                                if process.returncode not in {0, -15}:
                                    log.seek(0)
                                    print(log.read()[-4000:])


if __name__ == "__main__":
    asyncio.run(main())
