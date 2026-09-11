import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, SESSION_EXPIRED_EVENT } from "./api";
import type { SessionUser } from "./types";

type AuthContextValue = {
  user: SessionUser | null;
  loading: boolean;
  // True until both /auth/me and /auth/setup-status have settled.
  needsSetup: boolean;
  login: (username: string, password: string) => Promise<void>;
  loginWithAdfs: (returnTo?: string) => void;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  // Performs first-time setup, claiming the seeded admin account with the
  // chosen password and returning an authenticated session.
  setup: (password: string) => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);
const LOGIN_METHOD_COOKIE_NAME = "cm_login_method";
const ADFS_AUTO_ATTEMPT_KEY = "cm_adfs_auto_attempted";

function hasAdfsLoginPreference(): boolean {
  return document.cookie
    .split("; ")
    .some((entry) => entry === `${LOGIN_METHOD_COOKIE_NAME}=adfs`);
}

export function safeReturnPath(value: string | null | undefined): string {
  if (
    !value ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    return "/";
  }
  try {
    const parsed = new URL(value, window.location.origin);
    if (parsed.origin !== window.location.origin) return "/";
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return "/";
  }
}

export function requestedReturnPath(): string {
  const requested = new URLSearchParams(window.location.search).get("returnTo");
  if (requested) return safeReturnPath(requested);
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  return safeReturnPath(current);
}

function startAdfsLogin(returnTo: string): void {
  const query = new URLSearchParams({ returnTo: safeReturnPath(returnTo) });
  window.location.assign(`/api/auth/adfs/start?${query.toString()}`);
}

function tryAutomaticAdfsLogin(): boolean {
  const adfsResult = new URLSearchParams(window.location.search).get("adfs");
  if (
    adfsResult ||
    !hasAdfsLoginPreference() ||
    sessionStorage.getItem(ADFS_AUTO_ATTEMPT_KEY) === "true"
  ) {
    return false;
  }
  sessionStorage.setItem(ADFS_AUTO_ATTEMPT_KEY, "true");
  startAdfsLogin(requestedReturnPath());
  return true;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const me = await api.get<SessionUser>("/auth/me");
      setUser(me);
      sessionStorage.removeItem(ADFS_AUTO_ATTEMPT_KEY);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        if (tryAutomaticAdfsLogin()) return;
        setUser(null);
      } else {
        setUser(null);
      }
    }
  }, []);

  const refreshSetupStatus = useCallback(async () => {
    try {
      const status = await api.get<{ needsSetup: boolean }>("/auth/setup-status");
      setNeedsSetup(!!status.needsSetup);
    } catch {
      // Network or server failure: assume setup is not needed so we fall
      // back to the standard login screen and surface the real auth error
      // there instead of trapping the user on /setup.
      setNeedsSetup(false);
    }
  }, []);

  useEffect(() => {
    Promise.all([refresh(), refreshSetupStatus()]).finally(() => setLoading(false));
  }, [refresh, refreshSetupStatus]);

  // Any authenticated API request can be the first one to discover that the
  // server-side session expired. Clear auth immediately so ProtectedRoutes
  // redirects to /login instead of leaving an empty page behind.
  useEffect(() => {
    const handleSessionExpired = () => {
      if (!tryAutomaticAdfsLogin()) setUser(null);
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, handleSessionExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, handleSessionExpired);
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      const me = await api.post<SessionUser>("/auth/login", { username, password });
      setUser(me);
    },
    [],
  );

  const loginWithAdfs = useCallback((returnTo = requestedReturnPath()) => {
    startAdfsLogin(returnTo);
  }, []);

  const setup = useCallback(
    async (password: string) => {
      try {
        const me = await api.post<SessionUser>("/auth/setup", { password });
        setUser(me);
        setNeedsSetup(false);
      } catch (err) {
        // 409 means another actor (or a previous tab) already claimed the
        // admin account. Re-fetch setup-status so the UI flips to the
        // login screen instead of stranding the user on /setup forever.
        if (err instanceof ApiError && err.status === 409) {
          await refreshSetupStatus();
        }
        throw err;
      }
    },
    [refreshSetupStatus],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // ignore
    }
    document.cookie = `${LOGIN_METHOD_COOKIE_NAME}=; Max-Age=0; Path=/`;
    sessionStorage.removeItem(ADFS_AUTO_ATTEMPT_KEY);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, needsSetup, login, loginWithAdfs, logout, refresh, setup }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
