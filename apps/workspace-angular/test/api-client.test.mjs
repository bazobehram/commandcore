import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "../src/app/api-client.ts";

async function withFetch(mockFetch, assertion) {
  const original = globalThis.fetch;
  globalThis.fetch = mockFetch;
  try {
    await assertion();
  } finally {
    globalThis.fetch = original;
  }
}

test("session GET uses same-origin cookies, disables cache, and never adds auth headers", async () => {
  await withFetch(
    async (path, options) => {
      assert.equal(path, "/api/session");
      assert.deepEqual(options, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: {},
        body: undefined,
      });
      return {
        ok: true,
        json: async () => ({ authenticated: true, subject: "test-user" }),
      };
    },
    async () => {
      assert.deepEqual(await request("/api/session"), {
        authenticated: true,
        subject: "test-user",
      });
    },
  );
});

test("logout DELETE sends no body and does not follow an Auth0 redirect itself", async () => {
  await withFetch(
    async (path, options) => {
      assert.equal(path, "/api/session");
      assert.equal(options.method, "DELETE");
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.cache, "no-store");
      assert.equal(options.body, undefined);
      assert.deepEqual(options.headers, {});
      return { ok: true, json: async () => ({ ok: true }) };
    },
    async () => {
      assert.deepEqual(await request("/api/session", "DELETE"), { ok: true });
    },
  );
});

test("permission-changing PUT includes JSON, but no client-supplied authorization token", async () => {
  const body = { profile: "STANDARD", expected_profile: "STANDARD" };
  await withFetch(
    async (path, options) => {
      assert.equal(path, "/api/managed-devices/demo/my-permission");
      assert.equal(options.method, "PUT");
      assert.deepEqual(options.headers, { "Content-Type": "application/json" });
      assert.equal(options.body, JSON.stringify(body));
      assert.equal(options.credentials, "same-origin");
      return { ok: true, json: async () => ({ profile: "STANDARD" }) };
    },
    async () => {
      assert.deepEqual(
        await request("/api/managed-devices/demo/my-permission", "PUT", body),
        { profile: "STANDARD" },
      );
    },
  );
});

test("401 preserves HTTP status for the caller session-expired state", async () => {
  await withFetch(
    async () => ({
      ok: false,
      status: 401,
      json: async () => ({ detail: "unauthorized" }),
    }),
    async () => {
      await assert.rejects(request("/api/session"), (error) => {
        assert.equal(error.message, "unauthorized");
        assert.equal(error.status, 401);
        return true;
      });
    },
  );
});

test("fallback handles non-JSON failures without leaking response text", async () => {
  await withFetch(
    async () => ({
      ok: false,
      status: 503,
      json: async () => {
        throw new SyntaxError("invalid JSON");
      },
    }),
    async () => {
      await assert.rejects(request("/api/devices"), (error) => {
        assert.equal(error.message, "HTTP 503");
        assert.equal(error.status, 503);
        return true;
      });
    },
  );
});

test("non-JSON successful responses preserve previous empty-object behavior", async () => {
  await withFetch(
    async () => ({
      ok: true,
      json: async () => {
        throw new Error("empty body");
      },
    }),
    async () => {
      assert.deepEqual(await request("/api/empty"), {});
    },
  );
});

test("a failed same-origin request is not retried implicitly", async () => {
  let calls = 0;
  await withFetch(
    async () => {
      calls += 1;
      throw new Error("offline");
    },
    async () => {
      await assert.rejects(
        request("/api/managed-devices/demo", "PATCH", { display_name: "New" }),
        /offline/,
      );
      assert.equal(calls, 1);
    },
  );
});
