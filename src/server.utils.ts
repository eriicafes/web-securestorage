import type { HeaderSelector, SecureStorageRequest } from "./server";

export interface WebRequestEvent {
  request: Request;
  headers: Headers;
}

/** Creates a request adapter for Web request events. */
export function webRequest(): SecureStorageRequest<WebRequestEvent> {
  return {
    header(event, name) {
      return event.request.headers.get(name);
    },
    getCookie(event, name) {
      const header = event.request.headers.get("Cookie");
      if (!header) return undefined;

      for (const part of header.split(";")) {
        const separator = part.indexOf("=");
        if (separator < 0) continue;

        const cookieName = part.slice(0, separator).trim();
        if (cookieName === name) return part.slice(separator + 1).trim();
      }

      return undefined;
    },
    setCookie(_event, name, value, options) {
      const parts = [`${name}=${value}`];
      if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
      if (options.path) parts.push(`Path=${options.path}`);
      if (options.httpOnly) parts.push("HttpOnly");
      if (options.secure) parts.push("Secure");
      if (options.sameSite === true) parts.push("SameSite=Strict");
      if (options.sameSite === "strict") parts.push("SameSite=Strict");
      if (options.sameSite === "lax") parts.push("SameSite=Lax");
      if (options.sameSite === "none") parts.push("SameSite=None");
      _event.headers.append("Set-Cookie", parts.join("; "));
    },
  };
}

/** Creates a Web request event. */
export function webRequestEvent(
  request: Request,
  headers: Headers = new Headers(),
): WebRequestEvent {
  return { request, headers };
}

/** Reads a Bearer token from a request header. Default: `Authorization`. */
export function bearerToken(name = "Authorization"): HeaderSelector {
  return {
    name,
    transform(value) {
      if (!value.startsWith("Bearer ")) return undefined;
      return value.slice(7);
    },
  };
}
