import { createHash, createPublicKey, randomBytes } from "node:crypto";
import jwt, { type JwtPayload } from "jsonwebtoken";
import type { Request, Response } from "express";
import { fetch } from "undici";
import { signAuthState, verifyAuthState } from "./auth";

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
};

export type AdfsClaims = {
  subject: string;
  username: string;
  email: string | null;
  fullName: string;
};

let discoveryCache: { expiresAt: number; value: DiscoveryDocument } | null = null;

function env(name: string): string {
  return (process.env[name] ?? "").trim();
}

function issuer(): string {
  return env("ADFS_OIDC_ISSUER").replace(/\/+$/, "");
}

export function isAdfsConfigured(): boolean {
  return Boolean(issuer() && env("ADFS_CLIENT_ID") && env("ADFS_CLIENT_SECRET") && env("ADFS_REDIRECT_URI"));
}

function requireConfiguration(): void {
  if (!isAdfsConfigured()) {
    throw new Error(
      "ADFS SSO is not configured. Set ADFS_OIDC_ISSUER, ADFS_CLIENT_ID, " +
        "ADFS_CLIENT_SECRET, and ADFS_REDIRECT_URI.",
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

function getDiscovery(): Promise<DiscoveryDocument> {
  requireConfiguration();
  if (discoveryCache && discoveryCache.expiresAt > Date.now()) return Promise.resolve(discoveryCache.value);
  return fetch(`${issuer()}/.well-known/openid-configuration`)
    .then(async (response) => {
      if (!response.ok) throw new Error(`ADFS discovery returned HTTP ${response.status}`);
      const value = (await response.json()) as DiscoveryDocument;
      if (!value.authorization_endpoint || !value.token_endpoint || !value.jwks_uri) {
        throw new Error("ADFS discovery document is missing an OAuth endpoint");
      }
      discoveryCache = { expiresAt: Date.now() + 5 * 60 * 1000, value };
      return value;
    });
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
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

export function extractAdfsClaims(payload: JwtPayload): AdfsClaims {
  const claims = payload as Record<string, unknown>;
  const configuredUsernameClaim = env("ADFS_USERNAME_CLAIM") || "upn";
  const username =
    readClaim(claims, configuredUsernameClaim, ...claimNames(configuredUsernameClaim)) ??
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
  const discovery = await getDiscovery();
  const state = base64Url(randomBytes(32));
  const nonce = base64Url(randomBytes(32));
  const codeVerifier = base64Url(randomBytes(32));
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const signedState = signAuthState({ state, nonce, codeVerifier });
  res.cookie(STATE_COOKIE, signedState, cookieOptions(req));

  const url = new URL(discovery.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: env("ADFS_CLIENT_ID"),
    response_type: "code",
    redirect_uri: env("ADFS_REDIRECT_URI"),
    response_mode: "query",
    scope: env("ADFS_SCOPE") || "openid profile email",
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

async function exchangeCode(code: string, state: AdfsState, discovery: DiscoveryDocument) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env("ADFS_CLIENT_ID"),
    client_secret: env("ADFS_CLIENT_SECRET"),
    code,
    redirect_uri: env("ADFS_REDIRECT_URI"),
    code_verifier: state.codeVerifier,
  });
  const response = await fetch(discovery.token_endpoint, {
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

async function validateIdToken(idToken: string, state: AdfsState, discovery: DiscoveryDocument): Promise<AdfsClaims> {
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || typeof decoded === "string" || !decoded.header.kid) throw new Error("Invalid ADFS ID token");
  const jwksResponse = await fetch(discovery.jwks_uri, { headers: { accept: "application/json" } });
  if (!jwksResponse.ok) throw new Error(`ADFS JWKS returned HTTP ${jwksResponse.status}`);
  const jwks = (await jwksResponse.json()) as {
    keys?: Array<Record<string, unknown> & { kid?: string; alg?: string; use?: string }>;
  };
  const jwk = jwks.keys?.find((key) => key.kid === decoded.header.kid);
  if (!jwk) throw new Error("ADFS signing key was not found");

  const publicKey = createPublicKey({ key: jwk as any, format: "jwk" });
  const payload = jwt.verify(idToken, publicKey, {
    algorithms: ["RS256"],
    issuer: discovery.issuer || issuer(),
    audience: env("ADFS_CLIENT_ID"),
  }) as JwtPayload;
  if (payload.nonce !== state.nonce) throw new Error("ADFS nonce mismatch");
  return extractAdfsClaims(payload);
}

export async function finishAdfsLogin(req: Request, res: Response): Promise<AdfsClaims> {
  const state = readState(req);
  res.clearCookie(STATE_COOKIE, { path: "/api/auth/adfs" });
  if (typeof req.query.code !== "string" || !req.query.code) throw new Error("ADFS did not return an authorization code");
  const discovery = await getDiscovery();
  const idToken = await exchangeCode(req.query.code, state, discovery);
  return validateIdToken(idToken, state, discovery);
}