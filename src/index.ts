const SECURE_STORAGE_HEADER = "X-Web-SecureStorage";

/**
 * Returns the `RequestInit` that opts a request in to securestorage: adds
 * the `X-Web-SecureStorage` header, and sets `credentials: "include"` so the
 * server can store values securely as cookies even for cross-origin
 * requests.
 *
 * Further authenticated requests should use a regular fetch. For
 * cross-origin requests, the server should configure CORS with credentials
 * allowed, and the client should include credentials.
 */
export function secureFetchOptions(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  headers.set(SECURE_STORAGE_HEADER, "true");
  return { ...init, headers, credentials: "include" };
}

/** SecureStorage client. */
export const secureStorage = {
  /**
   * Makes a request that opts in to securestorage. Adds the
   * `X-Web-SecureStorage` header, and sets `credentials: "include"` so the
   * server can store values securely as cookies even for cross-origin
   * requests.
   *
   * Further authenticated requests should use a regular fetch. For
   * cross-origin requests, the server should configure CORS with
   * credentials allowed, and the client should include credentials.
   */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return globalThis.fetch(input, secureFetchOptions(init));
  },
};
