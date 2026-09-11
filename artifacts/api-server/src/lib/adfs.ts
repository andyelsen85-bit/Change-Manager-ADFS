import { createHash, createPublicKey, randomBytes } from "node:crypto";
import { rootCertificates } from "node:tls";
import jwt, { type JwtPayload } from "jsonwebtoken";
import type { Request, Response } from "express";
import { Agent, fetch } from "undici";
import { eq } from "drizzle-orm";
import { adfsSettingsTable, db } from "@workspace/db";
import { signAuthState, verifyAuthState } from "./auth";
import { decryptSecret } from "./secret-crypto";

const NODE_ENV = process.env["NODE_ENV"] ?? "development";
const STATE_COOKIE = "cm_adfs_state";
const STATE_TTL_SECONDS = 10 * 60;

type DiscoveryDocument = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};

type AdfsState = {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnPath: string;
};

export type AdfsClaims = {
  subject: string;
  username: string;
  email: string | null;
  fullName: string;
};

export type AdfsRuntimeConfig = {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  usernameClaim: string;
  autoProvision: boolean;
  caCertificatePem: string;
};

let discoveryCache: { issuer: string; caHash: string; expiresAt: number; value: DiscoveryDocument } | null = null;
let tlsAgentCache: { caHash: string; agent: Agent } | null = null;

function env(name: string): string {
  return (process.env[name] ?? "").trim();
}

function envConfiguration(): AdfsRuntimeConfig {
  return {
    enabled: true,
    issuer: env("ADFS_OIDC_ISSUER").replace(/\/+$/, ""),
    clientId: env("ADFS_CLIENT_ID"),
    clientSecret: env("ADFS_CLIENT_SECRET"),
    redirectUri: env("ADFS_REDIRECT_URI"),
    scope: env("ADFS_SCOPE") || "openid profile email",
    usernameClaim: env("ADFS_USERNAME_CLAIM") || "upn",
    autoProvision: env("ADFS_AUTO_PROVISION") === "true",
    caCertificatePem: env("ADFS_CA_CERT_PEM"),
  };
}

export async function getAdfsConfiguration(): Promise<AdfsRuntimeConfig> {
  const [row] = await db
    .select()
    .from(adfsSettingsTable)
    .where(eq(adfsSettingsTable.key, "global"));
  const hasStoredConfiguration = Boolean(
    row && (row.issuer || row.clientId || row.clientSecretEnc || row.redirectUri),
  );
  if (!hasStoredConfiguration) return envConfiguration();
  return {
    enabled: row.enabled,
    issuer: row.issuer.replace(/\/+$/, ""),
    clientId: row.clientId,
    clientSecret: decryptSecret(row.clientSecretEnc),
    redirectUri: row.redirectUri,
    scope: row.scope || "openid profile email",
    usernameClaim: row.usernameClaim || "upn",
    autoProvision: row.autoProvision,
    caCertificatePem: row.caCertificatePem ?? "",
  };
}

export async function isAdfsConfigured(): Promise<boolean> {
  const config = await getAdfsConfiguration();
  return Boolean(
    config.enabled &&
      config.issuer &&
      config.clientId &&
      config.redirectUri,
  );
}

function requireConfiguration(config: AdfsRuntimeConfig): void {
  if (
    !config.enabled ||
    !config.issuer ||
    !config.clientId ||
    !config.redirectUri
  ) {
    throw new Error(
      "ADFS SSO is disabled or incomplete. Configure it in Settings → ADFS.",
    );
  }
}

function cookieOptions(req: Request) {
  const secure = req.secure || req.protocol === "https" || NODE_ENV === "production";
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure,
    maxAge: STATE_TTL_SECONDS * 1000,
    path: "/api/auth/adfs",
  };
}

function caHash(config: AdfsRuntimeConfig): string {
  return config.caCertificatePem
    ? createHash("sha256").update(config.caCertificatePem).digest("hex")
    : "";
}

function adfsFetch(
  config: AdfsRuntimeConfig,
  url: string,
  init?: Parameters<typeof fetch>[1],
) {
  if (!config.caCertificatePem) return fetch(url, init);
  const hash = caHash(config);
  if (!tlsAgentCache || tlsAgentCache.caHash !== hash) {
    void tlsAgentCache?.agent.close();
    tlsAgentCache = {
      caHash: hash,
      agent: new Agent({
        connect: { ca: [...rootCertificates, config.caCertificatePem] },
      }),
    };
  }
  return fetch(url, { ...init, dispatcher: tlsAgentCache.agent });
}

function getDiscovery(config: AdfsRuntimeConfig, allowDisabled = false): Promise<DiscoveryDocument> {
  if (!allowDisabled) requireConfiguration(config);
  if (!config.issuer) throw new Error("ADFS issuer is required");
  if (
    discoveryCache &&
    discoveryCache.issuer === config.issuer &&
    discoveryCache.caHash === caHash(config) &&
    discoveryCache.expiresAt > Date.now()
  ) {
    return Promise.resolve(discoveryCache.value);
  }
  return adfsFetch(config, `${config.issuer}/.well-known/openid-configuration`)
    .then(async (response) => {
      if (!response.ok) throw new Error(`ADFS discovery returned HTTP ${response.status}`);
      const value = (await response.json()) as DiscoveryDocument;
      if (!value.authorization_endpoint || !value.token_endpoint || !value.jwks_uri) {
        throw new Error("ADFS discovery document is missing an OAuth endpoint");
      }
      discoveryCache = {
        issuer: config.issuer,
        caHash: caHash(config),
        expiresAt: Date.now() + 5 * 60 * 1000,
        value,
      };
      return value;
    });
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function sanitizeAdfsReturnPath(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    return "/";
  }
  try {
    const base = new URL("https://change-it.invalid");
    const parsed = new URL(value, base);
    if (parsed.origin !== base.origin) return "/";
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return "/";
  }
}

function readClaim(claims: Record<string, unknown>, ...names: string[]): string | null {
  for (const name of names) {
    const value = claims[name];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function claimNames(name: string): string[] {
  return [
    name,
    `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/${name}`,
    `http://schemas.microsoft.com/ws/2008/06/identity/claims/${name}`,
  ];
}

export function extractAdfsClaims(payload: JwtPayload, usernameClaim = "upn"): AdfsClaims {
  const claims = payload as Record<string, unknown>;
  const username =
    readClaim(claims, usernameClaim, ...claimNames(usernameClaim)) ??
    readClaim(claims, ...claimNames("preferred_username"), ...claimNames("email")) ??
    payload.sub ??
    "";
  const email = readClaim(claims, ...claimNames("email"), ...claimNames("upn"));
  const fullName =
    readClaim(claims, ...claimNames("name"), ...claimNames("displayName"), ...claimNames("given_name")) ??
    username;
  if (!payload.sub || !username) throw new Error("ADFS token did not contain a usable user identity");
  return { subject: payload.sub, username, email, fullName };
}

export async function beginAdfsLogin(req: Request, res: Response): Promise<void> {
  const config = await getAdfsConfiguration();
  const discovery = await getDiscovery(config);
  const state = base64Url(randomBytes(32));
  const nonce = base64Url(randomBytes(32));
  const codeVerifier = base64Url(randomBytes(32));
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const returnPath = sanitizeAdfsReturnPath(req.query.returnTo);
  const signedState = signAuthState({ state, nonce, codeVerifier, returnPath });
  res.cookie(STATE_COOKIE, signedState, cookieOptions(req));

  const url = new URL(discovery.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: config.redirectUri,
    response_mode: "query",
    scope: config.scope,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  }).toString();
  res.redirect(url.toString());
}

function readState(req: Request): AdfsState {
  const raw = req.cookies?.[STATE_COOKIE];
  if (!raw) throw new Error("Missing ADFS login state");
  const state = verifyAuthState<AdfsState>(raw);
  if (!state?.state || !state.nonce || !state.codeVerifier) throw new Error("Invalid or expired ADFS login state");
  if (state.state !== req.query.state) throw new Error("ADFS login state mismatch");
  return state;
}

async function exchangeCode(
  code: string,
  state: AdfsState,
  discovery: DiscoveryDocument,
  config: AdfsRuntimeConfig,
) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    code,
    redirect_uri: config.redirectUri,
    code_verifier: state.codeVerifier,
  });
  if (config.clientSecret) {
    body.set("client_secret", config.clientSecret);
  }
  const response = await adfsFetch(config, discovery.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
  });
  const payload = (await response.json()) as { id_token?: string; error?: string; error_description?: string };
  if (!response.ok || !payload.id_token) {
    throw new Error(payload.error_description || payload.error || `ADFS token exchange returned HTTP ${response.status}`);
  }
  return payload.id_token;
}

async function validateIdToken(
  idToken: string,
  state: AdfsState,
  discovery: DiscoveryDocument,
  config: AdfsRuntimeConfig,
): Promise<AdfsClaims> {
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || typeof decoded === "string" || !decoded.header.kid) throw new Error("Invalid ADFS ID token");
  const jwksResponse = await adfsFetch(config, discovery.jwks_uri, { headers: { accept: "application/json" } });
  if (!jwksResponse.ok) throw new Error(`ADFS JWKS returned HTTP ${jwksResponse.status}`);
  const jwks = (await jwksResponse.json()) as {
    keys?: Array<Record<string, unknown> & { kid?: string; alg?: string; use?: string }>;
  };
  const jwk = jwks.keys?.find((key) => key.kid === decoded.header.kid);
  if (!jwk) throw new Error("ADFS signing key was not found");

  const publicKey = createPublicKey({ key: jwk as any, format: "jwk" });
  const payload = jwt.verify(idToken, publicKey, {
    algorithms: ["RS256"],
    issuer: discovery.issuer || config.issuer,
    audience: config.clientId,
  }) as JwtPayload;
  if (payload.nonce !== state.nonce) throw new Error("ADFS nonce mismatch");
  return extractAdfsClaims(payload, config.usernameClaim);
}

export async function finishAdfsLogin(
  req: Request,
  res: Response,
): Promise<{ claims: AdfsClaims; returnPath: string }> {
  const state = readState(req);
  res.clearCookie(STATE_COOKIE, { path: "/api/auth/adfs" });
  if (typeof req.query.code !== "string" || !req.query.code) throw new Error("ADFS did not return an authorization code");
  const config = await getAdfsConfiguration();
  const discovery = await getDiscovery(config);
  const idToken = await exchangeCode(req.query.code, state, discovery, config);
  const claims = await validateIdToken(idToken, state, discovery, config);
  return { claims, returnPath: sanitizeAdfsReturnPath(state.returnPath) };
}

export async function testAdfsConfiguration(): Promise<{
  success: boolean;
  message: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
}> {
  const config = await getAdfsConfiguration();
  if (!config.issuer) {
    return { success: false, message: "Save an ADFS issuer before testing." };
  }
  try {
    const discovery = await getDiscovery(config, true);
    return {
      success: true,
      message: "ADFS discovery document loaded successfully.",
      issuer: discovery.issuer,
      authorizationEndpoint: discovery.authorization_endpoint,
      tokenEndpoint: discovery.token_endpoint,
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : "ADFS discovery test failed.",
    };
  }
}