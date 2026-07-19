export const SECURE_STORAGE_HEADER = "X-Web-SecureStorage";

export { bearerToken, webRequest, webRequestEvent } from "./server.utils";
export type { WebRequestEvent } from "./server.utils";

const DEFAULT_MAX_AGE = 60 * 60 * 24 * 365; // 365 days
const MIN_SIGNING_KEY_LENGTH = 32;

export interface CookieOptions {
  httpOnly?: boolean;
  path?: string;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none" | boolean;
  maxAge?: number;
}

export interface SecureStorageRequest<Event> {
  header(event: Event, name: string): string | null;
  getCookie(event: Event, name: string): string | undefined;
  setCookie(
    event: Event,
    name: string,
    value: string,
    options: CookieOptions,
  ): void;
}

export interface HeaderSelector {
  name: string;
  transform?: (value: string) => string | undefined;
}

export interface Signer {
  sign(value: string): Promise<string>;
  verify(value: string): Promise<string>;
}

export interface SecureStorageServerOptions<
  Event,
  TSigner extends Signer | undefined = undefined,
> {
  /** Adapter for reading request cookies and headers, and writing cookies. */
  request: SecureStorageRequest<Event>;
  /**
   * Optional signer for signing values directly into cookies instead of
   * storing them in plain text. Create one with `createSigner`.
   */
  signer?: TSigner;
  /** Cookie attribute and read-behavior options. */
  cookies?: {
    /** Prefix for value cookie names. Default: `"sessionstorage."`. */
    prefix?: string;
    /** Path applied to cookies. Default: `"/"`. */
    path?: string;
    /** Whether cookies require HTTPS. Default: `true`. */
    secure?: boolean;
    /** SameSite mode applied to cookies. Default: `"lax"`. */
    sameSite?: "strict" | "lax" | "none" | boolean;
    /**
     * Default `Max-Age` for writes, in seconds. Can be overridden per write.
     * Default: one year.
     */
    maxAge?: number;
    /**
     * Deletes an invalid stored value on read. Can be overridden per read.
     * Default: `false`.
     */
    deleteOnError?: boolean;
  };
}

type SecureStorageResult<TSigner, T> = TSigner extends Signer ? Promise<T> : T;

/**
 * Server-side key/value store for protected data. Clients that cannot
 * securely store values themselves opt in via the `X-Web-SecureStorage`
 * header to get values moved out of the response and into HttpOnly cookies
 * instead. Pass a `signer` to sign values, whether they end up in a cookie
 * or are returned directly, so a tampered value fails verification.
 */
export class SecureStorageServer<
  Event,
  TSigner extends Signer | undefined = undefined,
> {
  private readonly request: SecureStorageRequest<Event>;
  private readonly signer?: TSigner;
  private readonly prefix: string;
  private readonly cookieOptions: CookieOptions;
  private readonly deleteOnError?: boolean;

  constructor(options: SecureStorageServerOptions<Event, TSigner>) {
    this.request = options.request;
    this.signer = options.signer;
    this.prefix = options.cookies?.prefix ?? "sessionstorage.";
    this.cookieOptions = {
      httpOnly: true,
      path: options.cookies?.path ?? "/",
      sameSite: options.cookies?.sameSite ?? "lax",
      secure: options.cookies?.secure ?? true,
      maxAge: options.cookies?.maxAge,
    };
    this.deleteOnError = options.cookies?.deleteOnError;
  }

  /** Reports whether a request opted in to securestorage. */
  isSecureStorageRequest(event: Event): boolean {
    return this.request.header(event, SECURE_STORAGE_HEADER) === "true";
  }

  write(
    event: Event,
    key: string,
    value: string,
    options: {
      /** Write `Max-Age`, in seconds. Defaults to the server `maxAge`. */
      maxAge?: number;
    } = {},
  ): SecureStorageResult<TSigner, string | null> {
    if (!this.isSecureStorageRequest(event)) {
      return (
        this.signer ? this.signer.sign(value) : value
      ) as SecureStorageResult<TSigner, string | null>;
    }

    const cookieName = `${this.prefix}${encodeURIComponent(key)}`;
    const maxAge =
      options.maxAge ?? this.cookieOptions.maxAge ?? DEFAULT_MAX_AGE;
    const cookieOptions = { ...this.cookieOptions, maxAge };

    if (!this.signer) {
      this.request.setCookie(
        event,
        cookieName,
        encodeURIComponent(value),
        cookieOptions,
      );
      return null as SecureStorageResult<TSigner, string | null>;
    }

    return this.signer.sign(value).then((signed) => {
      this.request.setCookie(
        event,
        cookieName,
        encodeURIComponent(signed),
        cookieOptions,
      );
      return null;
    }) as SecureStorageResult<TSigner, string | null>;
  }

  writeJSON<T>(
    event: Event,
    key: string,
    value: T,
    options: {
      /** Write `Max-Age`, in seconds. Defaults to the server `maxAge`. */
      maxAge?: number;
    } = {},
  ): SecureStorageResult<TSigner, string | null> {
    const serialized = JSON.stringify(value) ?? "null";
    return this.write(event, key, serialized, options) as SecureStorageResult<
      TSigner,
      string | null
    >;
  }

  read(
    event: Event,
    key: string,
    options: {
      /** Request header to read before reading cookie storage. */
      header?: string | HeaderSelector;
      /** Deletes the stored value if it is invalid. */
      deleteOnError?: boolean;
    } = {},
  ): SecureStorageResult<TSigner, string | null> {
    const headerValue = this.readHeader(event, options.header);
    if (headerValue !== null) {
      if (!this.signer) {
        return headerValue as SecureStorageResult<TSigner, string | null>;
      }
      return this.signer
        .verify(headerValue)
        .catch(() => null) as SecureStorageResult<TSigner, string | null>;
    }

    const cookieName = `${this.prefix}${encodeURIComponent(key)}`;
    const rawCookie = this.request.getCookie(event, cookieName);
    const deleteOnError = options.deleteOnError ?? this.deleteOnError;
    const raw = this.decodeCookieValue(rawCookie);

    if (rawCookie !== undefined && raw === null && deleteOnError) {
      this.delete(event, key);
    }

    if (!this.signer) {
      return raw as SecureStorageResult<TSigner, string | null>;
    }

    if (raw === null) {
      return Promise.resolve(null) as SecureStorageResult<
        TSigner,
        string | null
      >;
    }

    return this.signer.verify(raw).catch(() => {
      if (deleteOnError) {
        this.delete(event, key);
      }
      return null;
    }) as SecureStorageResult<TSigner, string | null>;
  }

  readJSON<T = unknown>(
    event: Event,
    key: string,
    options?: {
      /** Request header to read before reading to cookie storage. */
      header?: string | HeaderSelector;
      /** Deletes the stored value if it is invalid. */
      deleteOnError?: boolean;
    },
  ): SecureStorageResult<TSigner, T | null>;
  readJSON<TSchema extends AnyStandardSchema>(
    event: Event,
    key: string,
    options: {
      /** Request header to read before reading to cookie storage. */
      header?: string | HeaderSelector;
      /** Standard Schema compatible validator for the parsed value. */
      schema: TSchema;
      /** Deletes the stored value if it is invalid. */
      deleteOnError?: boolean;
    },
  ): SecureStorageResult<
    TSigner,
    StandardSchemaV1.InferSchemaOutput<TSchema> | null
  >;
  readJSON<T = unknown>(
    event: Event,
    key: string,
    options?: {
      /** Request header to read before reading to cookie storage. */
      header?: string | HeaderSelector;
      /** Standard Schema compatible validator for the parsed value. */
      schema?: AnyStandardSchema;
      /** Deletes the stored value if it is invalid. */
      deleteOnError?: boolean;
    },
  ): SecureStorageResult<TSigner, T | null> {
    const deleteOnError = options?.deleteOnError ?? this.deleteOnError;
    // A value read from the header opt-in was never stored in the cookie, so
    // a parse/validation failure here says nothing about the cookie's value.
    const fromHeader = this.readHeader(event, options?.header) !== null;

    if (!this.signer) {
      const value = this.read(event, key, options) as string | null;
      if (value === null) return null as SecureStorageResult<TSigner, T | null>;

      const parsed = options?.schema
        ? parse(value, options.schema)
        : parse(value);
      if (parsed === null && !fromHeader && deleteOnError) {
        this.delete(event, key);
      }
      return parsed as SecureStorageResult<TSigner, T | null>;
    }

    return (this.read(event, key, options) as Promise<string | null>).then(
      async (value) => {
        if (value === null) return null;

        const parsed = options?.schema
          ? parse(value, options.schema)
          : parse(value);
        if (parsed === null && !fromHeader && deleteOnError) {
          await (this.delete(event, key) as Promise<void>).catch(() => {
            // best effort
          });
        }
        return parsed;
      },
    ) as SecureStorageResult<TSigner, T | null>;
  }

  delete(event: Event, key: string): SecureStorageResult<TSigner, void> {
    const cookieName = `${this.prefix}${encodeURIComponent(key)}`;
    this.request.setCookie(event, cookieName, "", {
      ...this.cookieOptions,
      maxAge: 0,
    });
    return (this.signer ? Promise.resolve() : undefined) as SecureStorageResult<
      TSigner,
      void
    >;
  }

  private readHeader(
    event: Event,
    header?: string | HeaderSelector,
  ): string | null {
    if (typeof header === "string") {
      return this.request.header(event, header) || null;
    }
    if (header) {
      const value = this.request.header(event, header.name);
      if (!value) return null;
      return header.transform?.(value) || value;
    }
    return null;
  }

  private decodeCookieValue(raw: string | undefined): string | null {
    if (raw === undefined) return null;
    try {
      return decodeURIComponent(raw);
    } catch {
      return null;
    }
  }
}

/** Creates a `SecureStorageServer`. */
export function secureStorageServer<
  Event,
  TSigner extends Signer | undefined = undefined,
>(
  options: SecureStorageServerOptions<Event, TSigner>,
): SecureStorageServer<Event, TSigner> {
  return new SecureStorageServer(options);
}

class HmacSigner implements Signer {
  private readonly secret: string;
  private signingKey?: Promise<CryptoKey>;

  constructor(secret: string) {
    if (secret.length < MIN_SIGNING_KEY_LENGTH) {
      throw new Error(
        `signed cookies secret must be at least ${MIN_SIGNING_KEY_LENGTH} characters long.`,
      );
    }
    this.secret = secret;
  }

  async sign(value: string): Promise<string> {
    const key = await this.getSigningKey();
    const encodedValue = HmacSigner.encodeBase64Url(
      new TextEncoder().encode(value),
    );
    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(encodedValue),
    );
    return `${encodedValue}.${HmacSigner.encodeBase64Url(new Uint8Array(signature))}`;
  }

  async verify(signed: string): Promise<string> {
    const parts = signed.split(".", 2);
    if (parts.length !== 2) throw new Error("Invalid signed cookie value.");

    const encodedValue = parts[0];
    const encodedSignature = parts[1];
    const signature = HmacSigner.decodeBase64Url(encodedSignature);
    const key = await this.getSigningKey();
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(encodedValue),
    );
    if (!valid) throw new Error("Invalid signed cookie value.");
    return new TextDecoder().decode(HmacSigner.decodeBase64Url(encodedValue));
  }

  private getSigningKey(): Promise<CryptoKey> {
    this.signingKey ??= crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(this.secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
    return this.signingKey;
  }

  private static encodeBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  private static decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
}

/**
 * Creates a `Signer`. Values are signed with `secret`, so a tampered value
 * fails verification.
 */
export function createSigner(options: { secret: string }): Signer {
  return new HmacSigner(options.secret);
}

// --- Standard Schema ---------------------------------------------------

export interface StandardSchemaV1<Input = unknown, Output = Input> {
  readonly "~standard": StandardSchemaV1.Props<Input, Output>;
}

export declare namespace StandardSchemaV1 {
  export interface Props<Input = unknown, Output = Input> {
    readonly version: 1;
    readonly vendor: string;
    readonly validate: (
      value: unknown,
    ) => Result<Output> | Promise<Result<Output>>;
    readonly types?: {
      readonly input: Input;
      readonly output: Output;
    };
  }

  export type Result<Output> = SuccessResult<Output> | FailureResult;

  export interface SuccessResult<Output> {
    readonly value: Output;
    readonly issues?: undefined;
  }

  export interface FailureResult {
    readonly issues: ReadonlyArray<Issue>;
  }

  export interface Issue {
    readonly message: string;
    readonly path?:
      | ReadonlyArray<PropertyKey | { readonly key: PropertyKey }>
      | undefined;
  }

  export type InferSchemaOutput<TSchema> =
    TSchema extends StandardSchemaV1<any, infer TOutput> ? TOutput : unknown;
}

export type AnyStandardSchema = StandardSchemaV1<any, any>;

export function parse<T = unknown>(value: string): T | null;
export function parse<TSchema extends AnyStandardSchema>(
  value: string,
  schema: TSchema,
): StandardSchemaV1.InferSchemaOutput<TSchema> | null;
export function parse<
  T = unknown,
  TSchema extends AnyStandardSchema = AnyStandardSchema,
>(
  value: string,
  schema?: TSchema,
): T | StandardSchemaV1.InferSchemaOutput<TSchema> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!schema) return parsed as T;

  const result = schema["~standard"].validate(parsed);
  if (
    result !== null &&
    typeof result === "object" &&
    "then" in result &&
    typeof result.then === "function"
  ) {
    return null;
  }
  const resolved = result as StandardSchemaV1.Result<T>;
  if (resolved.issues) return null;
  return resolved.value;
}
