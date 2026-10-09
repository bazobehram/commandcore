import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const html = readFileSync("apps/web/activity-widget.html", "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, "activity widget script exists");

const tick = () => new Promise(resolve => setImmediate(resolve));

function harness({ nativeBridge = false } = {}) {
  class Element {
    constructor(tag = "div") {
      this.tag = tag;
      this.children = [];
      this.textContent = "";
      this.className = "";
      this.listeners = {};
    }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = [...items]; }
    addEventListener(event, callback) { this.listeners[event] = callback; }
    click() { this.listeners.click?.(); }
  }
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const requests = [];
  let rows = [];
  let interval = null;
  let messageHandler = null;
  const parent = {
    postMessage(message) {
      requests.push(message);
      if (!("id" in message)) return;
      const result = message.method === "tools/call"
        ? { structuredContent: { events: rows } }
        : { protocolVersion: "2026-01-26", hostCapabilities: { serverTools: {} } };
      queueMicrotask(() => messageHandler?.({
        source: parent,
        data: { jsonrpc: "2.0", id: message.id, result }
      }));
    }
  };
  const window = {
    parent,
    addEventListener(event, handler) {
      if (event === "message") messageHandler = handler;
    },
    ...(nativeBridge ? { openai: {
      callTool: async (name, args) => {
        requests.push({ method: "native-call", name, args });
        return { structuredContent: { events: rows } };
      }
    } } : {})
  };
  const document = {
    hidden: false,
    getElementById: get,
    createElement: tag => new Element(tag)
  };
  vm.runInNewContext(script, {
    window, document,
    setInterval(callback) { interval = callback; },
    setTimeout(callback, delay) {
      if (delay === 600) queueMicrotask(callback);
      return 1;
    },
    Date, Number, Promise, Map, Error
  }, { timeout: 2000 });
  return {
    elements, requests, document,
    setRows: values => { rows = values; },
    poll: () => interval(),
    click: id => get(id).click(),
    get: id => get(id)
  };
}

const row = (status, duration_ms = 1234) => ({
  id: "example", tool: "shell.exec", device: "test-node-a",
  status, duration_ms, started_at: "2026-10-09T05:00:00+00:00"
});

const app = harness();
app.setRows([row("running")]);
await tick();
await tick();
assert.equal(app.requests[0].method, "ui/initialize");
assert.equal(app.requests[0].params.appInfo.name, "CommandCore Live Activity");
assert.ok(app.requests.some(x => x.method === "ui/notifications/initialized"));
assert.ok(app.requests.some(x => x.method === "tools/call" && x.params.name === "activity.feed"));
assert.equal(app.get("state").textContent, "Live");
assert.equal(app.get("feed").children[0].className, "running");
assert.equal(app.get("feed").children[0].children[1].children[0].textContent, "shell.exec");

app.setRows([row("ok", 240)]);
app.poll();
await tick();
assert.equal(app.get("feed").children[0].className, "ok");
assert.match(app.get("feed").children[0].children[2].textContent, /Done · 240ms/);

app.setRows([row("timeout")]);
app.poll();
await tick();
assert.equal(app.get("feed").children[0].className, "error");

app.click("pause");
assert.equal(app.get("state").textContent, "Paused");
const count = app.requests.length;
app.poll();
await tick();
assert.equal(app.requests.length, count, "paused polls must be silent");

app.setRows([row("completed", 7)]);
app.click("refresh");
await tick();
assert.ok(app.requests.length > count, "manual refresh must work while paused");
assert.equal(app.get("feed").children[0].className, "ok");

app.document.hidden = true;
const countHidden = app.requests.length;
app.poll();
await tick();
assert.equal(app.requests.length, countHidden, "hidden widget must not poll");

const native = harness({ nativeBridge: true });
native.setRows([row("running")]);
await tick();
assert.ok(native.requests.some(x => x.method === "native-call" && x.name === "activity.feed"));
assert.ok(!native.requests.some(x => x.method === "ui/initialize"));

console.log("Activity widget smoke: PASS (MCP Apps handshake, live transitions, pause/manual refresh, hidden iframe, native bridge)");
