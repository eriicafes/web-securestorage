import { getCookie, H3, setCookie, type H3Event } from "h3";
import { describe, expect, test, vi } from "vitest";
import { z } from "zod";
import { secureFetchOptions } from "../src";
import {
  bearerToken,
  createSigner,
  SECURE_STORAGE_HEADER,
  secureStorageServer,
  webRequest,
  webRequestEvent,
  type SecureStorageRequest,
} from "../src/server";

describe("securestorage", () => {
  test("keeps normal API responses JSON-compatible without activation", async () => {
    const app = createServerApp();
    const response = await app.fetch(
      new Request("https://app.example.com/login"),
    );

    await expect(response.json()).resolves.toEqual({
      accessToken: "access-token",
      refreshToken: "refresh-token",
      profile: { id: 1, email: "ada@example.com" },
    });
    expect(response.headers.get("Set-Cookie")).toBeNull();
  });

  test("activated fetch stores values in cookies and returns nulls instead", async () => {
    const app = createServerApp();
    const session = createBrowserSession(app);

    const response = await session.fetch(
      "https://app.example.com/login",
      secureFetchOptions(),
    );

    await expect(response.json()).resolves.toEqual({
      accessToken: null,
      refreshToken: null,
      profile: { id: 1, email: "ada@example.com" },
    });
    expect(session.findSetCookie("sessionstorage.accessToken")).toContain(
      "HttpOnly",
    );

    const me = await session.fetch(
      "https://app.example.com/me",
      secureFetchOptions(),
    );
    await expect(me.json()).resolves.toEqual({
      accessToken: "access-token",
      refreshToken: "refresh-token",
    });

    const normalMe = await session.fetch("https://app.example.com/me");
    await expect(normalMe.json()).resolves.toEqual({
      accessToken: "access-token",
      refreshToken: "refresh-token",
    });
  });

  test("write can override cookie maxAge per value", async () => {
    const app = new H3();
    const storage = secureStorageServer({
      request: createH3Request(),
      cookies: { secure: false },
    });
    const session = createBrowserSession(app);

    app.get("/write", (event) => ({
      token: storage.write(event, "token", "abc", { maxAge: 60 }),
    }));

    await session.fetch("https://app.example.com/write", secureFetchOptions());

    expect(session.findSetCookie("sessionstorage.token")).toContain(
      "Max-Age=60",
    );
  });

  test("preserves request init and custom fetch behaviour", async () => {
    const innerFetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init);
        return Response.json({
          method: request.method,
          header: request.headers.get("X-Web-SecureStorage"),
          body: await request.text(),
        });
      },
    );

    const response = await innerFetch(
      "https://app.example.com/echo",
      secureFetchOptions({ method: "POST", body: "hello" }),
    );

    await expect(response.json()).resolves.toEqual({
      method: "POST",
      header: "true",
      body: "hello",
    });
    expect(innerFetch).toHaveBeenCalledOnce();
  });
});

test("direct cookie write uses the per-write maxAge as-is, uncapped by server maxAge", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false, maxAge: 30 },
  });
  const session = createBrowserSession(app);

  app.get("/write", (event) => ({
    token: storage.write(event, "token", "abc", { maxAge: 60 }),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());

  expect(session.findSetCookie("sessionstorage.token")).toContain("Max-Age=60");
});

test("write applies default maxAge when no maxAge option is provided", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });
  const session = createBrowserSession(app);

  app.get("/write", (event) => ({
    token: storage.write(event, "token", "abc"),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());

  expect(session.findSetCookie("sessionstorage.token")).toContain(
    "Max-Age=31536000",
  );
});

test("writeJSON returns the JSON-stringified value, not the original object, when not activated", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });

  app.get("/write", (event) => ({
    user: storage.writeJSON(event, "user", { id: 1 }),
  }));

  await expect(
    (await app.fetch(new Request("https://app.example.com/write"))).json(),
  ).resolves.toEqual({ user: '{"id":1}' });
});

test("allows cookie storage to be provided behind an interface", async () => {
  const values = new Map<string, string>();
  const options = new Map<string, unknown>();
  const request: SecureStorageRequest<H3Event> = {
    header(event, name) {
      return event.req.headers.get(name);
    },
    getCookie(_event, key) {
      return values.get(key);
    },
    setCookie(_event, key, value, cookieOptions) {
      values.set(key, value);
      options.set(key, cookieOptions);
    },
  };
  const app = new H3();
  const storage = secureStorageServer({ request });

  app.get("/write", (event) => ({
    value: storage.writeJSON(event, "session", { id: 1 }),
  }));
  app.get("/read", (event) => ({
    value: storage.readJSON(event, "session"),
  }));

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/write", secureFetchOptions()),
      )
    ).json(),
  ).resolves.toEqual({ value: null });
  expect(values.get("sessionstorage.session")).toBe(
    encodeURIComponent('{"id":1}'),
  );
  expect(options.get("sessionstorage.session")).toEqual({
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secure: true,
    maxAge: 31536000,
  });
  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read", secureFetchOptions()),
      )
    ).json(),
  ).resolves.toEqual({ value: { id: 1 } });
});

test("cookie storage can be typed to a non-H3 event", () => {
  interface CustomEvent {
    headers: Headers;
    cookies: Map<string, string>;
  }

  const request: SecureStorageRequest<CustomEvent> = {
    header(event, name) {
      return event.headers.get(name);
    },
    getCookie(event, key) {
      return event.cookies.get(key);
    },
    setCookie(event, key, value) {
      event.cookies.set(key, value);
    },
  };
  const storage = secureStorageServer({ request });
  const event: CustomEvent = {
    headers: new Headers({ "X-Web-SecureStorage": "true" }),
    cookies: new Map(),
  };

  expect(storage.writeJSON(event, "session", { id: 1 })).toBeNull();
  expect(storage.readJSON(event, "session")).toEqual({ id: 1 });
});

test("webRequest creates an adapter for webRequestEvent", () => {
  const headers = new Headers();
  const request = new Request(
    "https://app.example.com/write",
    secureFetchOptions(),
  );
  const event = webRequestEvent(request, headers);
  const storage = secureStorageServer({
    request: webRequest(),
    cookies: { secure: false },
  });

  expect(event.headers).toBeInstanceOf(Headers);
  expect(event.headers).toBe(headers);
  expect(storage.write(event, "token", "abc")).toBeNull();

  const setCookie = getSetCookies(event.headers)[0];
  expect(setCookie).toContain("sessionstorage.token=abc");
  expect(setCookie).toContain("HttpOnly");

  const readStorage = secureStorageServer({
    request: webRequest(),
    cookies: { secure: false },
  });
  const readRequest = new Request("https://app.example.com/read", {
    headers: { Cookie: setCookie.split(";")[0] },
  });
  const readEvent = webRequestEvent(readRequest);

  expect(readStorage.read(readEvent, "token")).toBe("abc");
});

test("cookie values are percent-encoded so a naive adapter can't be corrupted by special characters", () => {
  const cookies = new Map<string, string>();
  const request: SecureStorageRequest<{ cookies: Map<string, string> }> = {
    header: (_event, name) => (name === SECURE_STORAGE_HEADER ? "true" : null),
    getCookie: (event, key) => event.cookies.get(key),
    setCookie: (event, key, value) => {
      event.cookies.set(key, value);
    },
  };
  const storage = secureStorageServer({ request });
  const event = { cookies };
  const value = "a;b,c\r\nSet-Cookie: evil=1";

  storage.write(event, "raw", value);

  expect(cookies.get("sessionstorage.raw")).toBe(encodeURIComponent(value));
  expect(cookies.get("sessionstorage.raw")).not.toMatch(/[;,\r\n]/);
  expect(storage.read(event, "raw")).toBe(value);
});

test("reads can use headers before falling back to storage", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });

  app.get("/read-header", (event) => ({
    token: storage.read(event, "token", { header: "Authorization" }),
  }));
  app.get("/read-header-json", (event) => ({
    session: storage.readJSON(event, "session", {
      header: bearerToken(),
    }),
  }));

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read-header", {
          headers: { Authorization: "Bearer abc" },
        }),
      )
    ).json(),
  ).resolves.toEqual({ token: "Bearer abc" });

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read-header-json", {
          headers: { Authorization: 'Bearer {"id":1}' },
        }),
      )
    ).json(),
  ).resolves.toEqual({ session: { id: 1 } });
});

test("read supports transformed headers, not just readJSON", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });

  app.get("/read-header", (event) => ({
    token: storage.read(event, "token", {
      header: bearerToken(),
    }),
  }));

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read-header", {
          headers: { Authorization: "Bearer abc" },
        }),
      )
    ).json(),
  ).resolves.toEqual({ token: "abc" });
});

test("bearerToken can read a custom header name", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });

  app.get("/read-header", (event) => ({
    token: storage.read(event, "token", {
      header: bearerToken("X-Token"),
    }),
  }));

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read-header", {
          headers: { "X-Token": "Bearer abc" },
        }),
      )
    ).json(),
  ).resolves.toEqual({ token: "abc" });
});

test("header options can transform a header value", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });

  app.get("/read-header", (event) => ({
    token: storage.read(event, "token", {
      header: {
        name: "X-Token",
        transform: (value) => value.trim(),
      },
    }),
  }));

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read-header", {
          headers: { "X-Token": " abc " },
        }),
      )
    ).json(),
  ).resolves.toEqual({ token: "abc" });
});

test("read falls through to cookie storage when the header is missing or empty", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });
  const session = createBrowserSession(app);

  app.get("/write", (event) => ({
    token: storage.write(event, "token", "abc"),
  }));
  app.get("/read", (event) => ({
    token: storage.read(event, "token", { header: "Authorization" }),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());

  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: "abc" });

  await expect(
    (
      await session.fetch(
        "https://app.example.com/read",
        secureFetchOptions({ headers: { Authorization: "" } }),
      )
    ).json(),
  ).resolves.toEqual({ token: "abc" });
});

test("read with a header selector verifies the header value with the signer", async () => {
  const app = new H3();
  const signer = createSigner({ secret: "top-secret-top-secret-top-secret" });
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer,
  });

  app.get("/read", async (event) => ({
    token: await storage.read(event, "token", { header: "Authorization" }),
  }));

  const signed = await signer.sign("abc");

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read", {
          headers: { Authorization: signed },
        }),
      )
    ).json(),
  ).resolves.toEqual({ token: "abc" });

  await expect(
    (
      await app.fetch(
        new Request("https://app.example.com/read", {
          headers: { Authorization: "not-signed" },
        }),
      )
    ).json(),
  ).resolves.toEqual({ token: null });
});

test("deleteOnError does not clear the stored cookie when an invalid header value fails parsing", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false, deleteOnError: true },
  });
  const session = createBrowserSession(app);

  app.get("/write", (event) => ({
    user: storage.writeJSON(event, "user", { id: 1 }),
  }));
  app.get("/read", (event) => ({
    user: storage.readJSON(event, "user", { header: "X-User" }),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  await expect(
    (
      await session.fetch(
        "https://app.example.com/read",
        secureFetchOptions({ headers: { "X-User": "not-json" } }),
      )
    ).json(),
  ).resolves.toEqual({ user: null });

  // The bad value came from the header, not the cookie, so the cookie
  // (which was never even read) must survive.
  expect(session.findSetCookie("Max-Age=0")).toBe("");
  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ user: { id: 1 } });
});

test("signer signs values directly in cookies and verifies them on read", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer: createSigner({ secret: "top-secret-top-secret-top-secret" }),
  });
  const session = createBrowserSession(app);

  app.get("/write", async (event) => ({
    token: await storage.write(event, "token", "abc"),
  }));
  app.get("/read", async (event) => ({
    token: await storage.read(event, "token"),
  }));

  await expect(
    (
      await session.fetch("https://app.example.com/write", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });

  const cookie = session.findSetCookie("sessionstorage.token");
  expect(cookie).toContain("HttpOnly");
  expect(cookie).not.toContain("=abc;");

  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: "abc" });
});

test("write and writeJSON sign pass-through values too, not just cookie-diverted ones", async () => {
  const app = new H3();
  const signer = createSigner({ secret: "top-secret-top-secret-top-secret" });
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer,
  });

  app.get("/write", async (event) => ({
    token: await storage.write(event, "token", "abc"),
    user: await storage.writeJSON(event, "user", { id: 1 }),
  }));

  const response = await app.fetch(
    new Request("https://app.example.com/write"),
  );
  expect(response.headers.get("Set-Cookie")).toBeNull();

  const body = await response.json();
  expect(body.token).not.toBe("abc");
  expect(body.token).toContain(".");
  await expect(signer.verify(body.token)).resolves.toBe("abc");

  expect(body.user).not.toBe('{"id":1}');
  expect(body.user).toContain(".");
  await expect(signer.verify(body.user)).resolves.toBe('{"id":1}');
});

test("signer rejects a tampered cookie value", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer: createSigner({ secret: "top-secret-top-secret-top-secret" }),
  });
  const session = createBrowserSession(app);

  app.get("/write", async (event) => ({
    token: await storage.write(event, "token", "abc"),
  }));
  app.get("/read", async (event) => ({
    token: await storage.read(event, "token"),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  session.tamperCookie("sessionstorage.token", "tampered.tampered");

  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });
  expect(session.findSetCookie("Max-Age=0")).toBe("");
});

test("signer deletes a tampered cookie when deleteOnError is enabled", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false, deleteOnError: true },
    signer: createSigner({ secret: "top-secret-top-secret-top-secret" }),
  });
  const session = createBrowserSession(app);

  app.get("/read", async (event) => ({
    token: await storage.read(event, "token"),
  }));

  session.tamperCookie("sessionstorage.token", "tampered.tampered");

  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });
  expect(session.findSetCookie("Max-Age=0")).toContain("sessionstorage.token");
});

test("read's deleteOnError option overrides the server default", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer: createSigner({ secret: "top-secret-top-secret-top-secret" }),
  });
  const session = createBrowserSession(app);

  app.get("/read", async (event) => ({
    token: await storage.read(event, "token", { deleteOnError: true }),
  }));

  session.tamperCookie("sessionstorage.token", "tampered.tampered");

  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });
  expect(session.findSetCookie("Max-Age=0")).toContain("sessionstorage.token");
});

test("signer treats a malformed signature as a failed verification", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer: createSigner({ secret: "top-secret-top-secret-top-secret" }),
  });
  const session = createBrowserSession(app);

  app.get("/read", async (event) => ({
    token: await storage.read(event, "token"),
  }));

  session.tamperCookie("sessionstorage.token", "abc.not-valid-base64!");

  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });
});

test("signer rejects a different secret", async () => {
  const app = new H3();
  const request = createH3Request();
  const writer = secureStorageServer({
    request,
    cookies: { secure: false },
    signer: createSigner({ secret: "secret-a-secret-a-secret-a-secret-a" }),
  });
  const reader = secureStorageServer({
    request,
    cookies: { secure: false },
    signer: createSigner({ secret: "secret-b-secret-b-secret-b-secret-b" }),
  });
  const session = createBrowserSession(app);

  app.get("/write", async (event) => ({
    token: await writer.write(event, "token", "abc"),
  }));
  app.get("/read", async (event) => ({
    token: await reader.read(event, "token"),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });
});

test("signer deletes by clearing the cookie", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
    signer: createSigner({ secret: "top-secret-top-secret-top-secret" }),
  });
  const session = createBrowserSession(app);

  app.get("/write", async (event) => ({
    token: await storage.write(event, "token", "abc"),
  }));
  app.get("/delete", async (event) => {
    await storage.delete(event, "token");
    return {};
  });
  app.get("/read", async (event) => ({
    token: await storage.read(event, "token"),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  await session.fetch("https://app.example.com/delete", secureFetchOptions());

  expect(session.findSetCookie("Max-Age=0")).toContain("sessionstorage.token");
  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ token: null });
});

test("validates server readJSON values with standard schema", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });
  const session = createBrowserSession(app);
  const schema = z.object({ id: z.number() });

  app.get("/write", (event) => ({
    user: storage.writeJSON(event, "user", { id: 1 }),
  }));
  app.get("/read", (event) => ({
    user: storage.readJSON(event, "user", { schema }),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ user: { id: 1 } });
});

test("returns null on schema validation failure and can remove bad cookie values", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false, deleteOnError: true },
  });
  const session = createBrowserSession(app);
  const schema = z.object({ id: z.number() });

  app.get("/write", (event) => ({
    user: storage.writeJSON(event, "user", { id: "bad" }),
  }));
  app.get("/read", (event) => ({
    user: storage.readJSON(event, "user", { schema }),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ user: null });

  expect(session.findSetCookie("Max-Age=0")).toContain("sessionstorage.user");
});

test("returns null on JSON parse failure and can remove bad cookie values", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false, deleteOnError: true },
  });
  const session = createBrowserSession(app);

  app.get("/write", (event) => ({
    user: storage.write(event, "user", "not-json"),
  }));
  app.get("/read", (event) => ({
    user: storage.readJSON(event, "user"),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());
  await expect(
    (
      await session.fetch("https://app.example.com/read", secureFetchOptions())
    ).json(),
  ).resolves.toEqual({ user: null });

  expect(session.findSetCookie("Max-Age=0")).toContain("sessionstorage.user");
});

test("exports an H3 request implementation", async () => {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });
  const session = createBrowserSession(app);

  app.get("/write", (event) => ({
    token: storage.write(event, "token", "abc"),
  }));

  await session.fetch("https://app.example.com/write", secureFetchOptions());

  expect(session.findSetCookie("sessionstorage.token")).toContain("HttpOnly");
});

function createH3Request(): SecureStorageRequest<H3Event> {
  return {
    header: (event, name) => event.req.headers.get(name),
    getCookie,
    setCookie,
  };
}

function createServerApp() {
  const app = new H3();
  const storage = secureStorageServer({
    request: createH3Request(),
    cookies: { secure: false },
  });

  app.get("/login", (event) => {
    return {
      accessToken: storage.write(event, "accessToken", "access-token"),
      refreshToken: storage.write(event, "refreshToken", "refresh-token"),
      profile: { id: 1, email: "ada@example.com" },
    };
  });

  app.get("/me", (event) => {
    return {
      accessToken: storage.read(event, "accessToken"),
      refreshToken: storage.read(event, "refreshToken"),
    };
  });

  return app;
}

function createBrowserSession(app: H3) {
  const cookies = new Map<string, string>();
  const setCookieHistory: string[] = [];

  const session = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const request = new Request(input, init);
      const headers = new Headers(request.headers);

      if (request.credentials !== "omit") {
        const cookie = [...cookies.entries()]
          .map(([name, value]) => `${name}=${value}`)
          .join("; ");
        if (cookie) headers.set("Cookie", cookie);
      }

      const response = await app.fetch(new Request(request, { headers }));
      const responseCookies = getSetCookies(response.headers);

      for (const cookie of responseCookies) {
        const [pair] = cookie.split(";").map((part) => part.trim());
        const separator = pair.indexOf("=");
        if (separator < 0) continue;
        const expired = cookie
          .split(";")
          .some((part) => part.trim().toLowerCase() === "max-age=0");
        setCookieHistory.push(cookie);
        if (expired) cookies.delete(pair.slice(0, separator));
        else cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
      }

      return response;
    },
    findSetCookie(fragment: string) {
      return setCookieHistory.find((cookie) => cookie.includes(fragment)) ?? "";
    },
    tamperCookie(name: string, value: string) {
      cookies.set(name, value);
    },
  };

  return session;
}

function getSetCookies(headers: Headers): string[] {
  const responseHeaders = headers as Headers & {
    getSetCookie?: () => string[];
  };
  const cookies = responseHeaders.getSetCookie?.();
  if (cookies) return cookies;

  const cookie = headers.get("Set-Cookie");
  if (!cookie) return [];
  return cookie.split(/,(?=[^;,]+=)/);
}
