# Web SecureStorage

`web-securestorage` moves selected values out of JSON API responses for browser
clients using `secureStorage.fetch`, while keeping normal API responses
unchanged.
Handlers call `write` when returning sensitive values and `read` when the value
is needed later.

Opted-in browser clients get `null` in the JSON response. Normal clients get
the original value.

## Installation

```sh
npm install web-securestorage
```

## Usage

Start by creating a server-side `secureStorage` instance. Use it in the routes
that return or read protected values.

### Quick start

#### H3

```ts
// server.ts
import { getCookie, H3, setCookie } from "h3";
import { secureStorageServer } from "web-securestorage/server";

const app = new H3();
const secureStorage = secureStorageServer({
  request: {
    header: (event, name) => event.req.headers.get(name),
    getCookie,
    setCookie,
  },
  cookies: { secure: true },
});

app.post("/login", async (event) => {
  const session = await login(event);

  return {
    accessToken: secureStorage.write(event, "accessToken", session.accessToken),
    refreshToken: secureStorage.write(
      event,
      "refreshToken",
      session.refreshToken,
    ),
    user: session.user,
  };
});

app.get("/me", async (event) => {
  const accessToken = secureStorage.read(event, "accessToken");
  const user = await authenticate(accessToken);

  return { user };
});
```

#### Next.js

Route handlers write onto response headers, not the request. `webRequest`
creates the request adapter, and `webRequestEvent` creates the per-request
event.

```ts
// app/login/route.ts
import { NextResponse, type NextRequest } from "next/server";
import {
  secureStorageServer,
  webRequest,
  webRequestEvent,
} from "web-securestorage/server";

const secureStorage = secureStorageServer({
  request: webRequest(),
  cookies: { secure: true },
});

export async function POST(request: NextRequest) {
  const session = await login(request);
  const event = webRequestEvent(request);

  return NextResponse.json(
    {
      accessToken: secureStorage.write(
        event,
        "accessToken",
        session.accessToken,
      ),
      refreshToken: secureStorage.write(
        event,
        "refreshToken",
        session.refreshToken,
      ),
      user: session.user,
    },
    { headers: event.headers },
  );
}
```

```ts
// app/me/route.ts
import { NextResponse, type NextRequest } from "next/server";
import {
  secureStorageServer,
  webRequest,
  webRequestEvent,
} from "web-securestorage/server";

const secureStorage = secureStorageServer({
  request: webRequest(),
  cookies: { secure: true },
});

export async function GET(request: NextRequest) {
  const event = webRequestEvent(request);

  const accessToken = secureStorage.read(event, "accessToken");
  const user = await authenticate(accessToken);

  return NextResponse.json({ user });
}
```

## Reading from headers

Pass `header` to `read` or `readJSON` to read the value from a request header
before reading stored values. This is useful for clients that do not use
securestorage and send the value back in a header instead.

```ts
secureStorage.read(event, "accessToken", { header: "X-API-Token" });
```

Use `bearerToken()` to read and strip a bearer token from the
`Authorization` header.

```ts
import { bearerToken } from "web-securestorage/server";

secureStorage.readJSON(event, "session", {
  header: bearerToken(),
});
```

Pass a header name to read from a different header.

```ts
secureStorage.read(event, "accessToken", {
  header: bearerToken("X-Access-Token"),
});
```

An empty header value is treated the same as a missing one, and the lookup
falls through to stored values.

## Client usage

Use `secureStorage.fetch` from the browser.

```ts
import { secureStorage } from "web-securestorage";

const response = await secureStorage.fetch("/login", {
  method: "POST",
  body: JSON.stringify({ email, password }),
});

await response.json();
// {
//   accessToken: null,
//   refreshToken: null,
//   user: { ... }
// }
```

If the same `/login` route is called with normal `fetch`, the response still
contains the original string values.

### Custom fetch

`secureFetchOptions` returns the `RequestInit` that opts a request in to
securestorage: the `X-Web-SecureStorage` header and `credentials: "include"`.
Use it with any fetch function your app already wraps.

```ts
import { secureFetchOptions } from "web-securestorage";

const response = await appFetch(
  "/login",
  secureFetchOptions({
    method: "POST",
    body: JSON.stringify({ email, password }),
  }),
);
```

For cross-origin API calls, configure CORS on the server to allow credentials
and the application origin. Further authenticated requests should keep
`credentials: "include"`.

## String storage

`write` and `read` work with string values.

```ts
secureStorage.write(event, "accessToken", "eyJhbGciOi...");
secureStorage.read(event, "accessToken"); // "eyJhbGciOi..."
```

When the request doesn't carry the `X-Web-SecureStorage` header, `write`
returns the value it was passed.

```ts
// normal fetch request
secureStorage.write(event, "accessToken", "abc123"); // "abc123"
```

This keeps API responses JSON-compatible unless the client explicitly opts into
securestorage behavior.

## Deleting values

Call `delete` to remove the stored cookie for a key if it is present.

```ts
secureStorage.delete(event, "accessToken");
```

## JSON storage

Use `writeJSON` and `readJSON` when values should be serialized with
`JSON.stringify` and parsed with `JSON.parse`.

```ts
interface Session {
  accessToken: string;
  refreshToken: string;
}

secureStorage.writeJSON(event, "session", {
  accessToken: "eyJhbGciOi...",
  refreshToken: "8xLp3f...",
});

const session = secureStorage.readJSON<Session>(event, "session");
console.log(session?.accessToken);
```

Unlike `write`, `writeJSON` always returns `string | null`: when the request
doesn't carry the header, it returns `JSON.stringify(value)` rather than the
original object. Put that string in a response header for clients that read
values back from headers instead of cookies (see
[Reading from headers](#reading-from-headers)).

Use `schema` when you want validation on reads. Schemas use the Standard Schema
interface, so libraries like Zod work.

```ts
import { z } from "zod";

const SessionSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
});

const session = secureStorage.readJSON(event, "session", {
  schema: SessionSchema,
});
```

If parsing or validation fails, `readJSON` returns `null`. Pass
`deleteOnError` when invalid stored values should be removed.

```ts
const session = secureStorage.readJSON(event, "session", {
  schema: SessionSchema,
  deleteOnError: true,
});
```

You can also set `deleteOnError` on the server instance.

```ts
const secureStorage = secureStorageServer({
  request,
  cookies: { deleteOnError: true },
});
```

## Custom request adapters

`secureStorageServer` is generic over the event type. A request adapter only
needs to read headers and stored values.

```ts
import {
  secureStorageServer,
  type CookieOptions,
  type SecureStorageRequest,
} from "web-securestorage/server";

interface Event {
  headers: Headers;
  cookies: Map<string, string>;
}

const request: SecureStorageRequest<Event> = {
  header(event, name) {
    return event.headers.get(name);
  },
  getCookie(event, name) {
    return event.cookies.get(name);
  },
  setCookie(event, name, value, options: CookieOptions) {
    persistCookie(event, name, value, options);
  },
};

const secureStorage = secureStorageServer({ request });
```

## Signing values

Pass `signer` to sign values. Values returned to requests that do not opt in
are signed too.

```ts
import { secureStorageServer, createSigner } from "web-securestorage/server";

const secureStorage = secureStorageServer({
  request,
  signer: createSigner({ secret: process.env.SECURE_STORAGE_SECRET! }),
});

secureStorage.writeJSON(event, "claims", {
  userId: "user_123",
  role: "admin",
});

const claims = secureStorage.readJSON<{ userId: string; role: string }>(
  event,
  "claims",
);
```

Invalid signed values read as `null`.

## Options

```ts
const secureStorage = secureStorageServer({
  request,
  signer,
  cookies: {
    path: "/",
    secure: true,
    sameSite: "lax",
    deleteOnError: false,
    maxAge: 60 * 60 * 24 * 365,
  },
});
```

- `request`: adapter for reading headers and stored values.
- `signer`: optional signer. Create one with `createSigner`.
- `cookies.path`: cookie path. Default: `"/"`.
- `cookies.secure`: whether cookies require HTTPS. Default: `true`.
- `cookies.sameSite`: cookie SameSite setting. Default: `"lax"`.
- `cookies.deleteOnError`: delete invalid values when read fails.
  Default: `false`.
- `cookies.maxAge`: default write `Max-Age` in seconds. Default: one year.

## License

MIT
