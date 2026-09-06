import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api, ApiError } from "../api/client";
import type { Membership, User } from "../api/types";

const CURRENT_TENANT_KEY = "agentguard.currentTenantId";

interface AuthContextValue {
  user: User | null;
  memberships: Membership[];
  currentTenantId: string | null;
  currentMembership: Membership | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (companyName: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  setCurrentTenantId: (tenantId: string) => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [currentTenantId, setCurrentTenantIdState] = useState<string | null>(
    () => localStorage.getItem(CURRENT_TENANT_KEY),
  );
  const [loading, setLoading] = useState(true);

  const setCurrentTenantId = useCallback((tenantId: string) => {
    localStorage.setItem(CURRENT_TENANT_KEY, tenantId);
    setCurrentTenantIdState(tenantId);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const me = await api.me();
      setUser(me.user);
      setMemberships(me.memberships);
      // If there's no stored tenant, or the stored one isn't one this user
      // is actually a member of (anymore), fall back to their first.
      setCurrentTenantIdState((prev) => {
        const stillValid = prev && me.memberships.some((m) => m.tenant_id === prev);
        if (stillValid) return prev;
        const fallback = me.memberships[0]?.tenant_id ?? null;
        if (fallback) localStorage.setItem(CURRENT_TENANT_KEY, fallback);
        return fallback;
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setUser(null);
        setMemberships([]);
      } else {
        throw err;
      }
    }
  }, []);

  useEffect(() => {
    refresh().finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(
    async (email: string, password: string) => {
      await api.login({ email, password });
      await refresh();
    },
    [refresh],
  );

  const signup = useCallback(
    async (companyName: string, email: string, password: string) => {
      await api.signup({ company_name: companyName, email, password });
      await refresh();
    },
    [refresh],
  );

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
    setMemberships([]);
  }, []);

  const currentMembership = useMemo(
    () => memberships.find((m) => m.tenant_id === currentTenantId) ?? null,
    [memberships, currentTenantId],
  );

  const value: AuthContextValue = {
    user,
    memberships,
    currentTenantId,
    currentMembership,
    loading,
    login,
    signup,
    logout,
    setCurrentTenantId,
    refresh,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
