import { useAuthStore } from "@/stores/auth";
import router from "@/router";
import { authMethod, baseURL, noAuth, logoutPage } from "./constants";
import { StatusError } from "@/api/utils";
import { setSafeTimeout } from "@/api/utils";

interface MeResponse {
  user: IUser;
  expiresAt: number;
}

async function fetchMe(): Promise<MeResponse> {
  const res = await fetch(`${baseURL}/api/auth/me`, {
    credentials: "same-origin",
  });

  if (res.status !== 200) {
    throw new StatusError(
      (await res.text()) || `${res.status} ${res.statusText}`,
      res.status
    );
  }

  return (await res.json()) as MeResponse;
}

function scheduleExpiry(expiresAt: number) {
  const authStore = useAuthStore();

  if (authStore.logoutTimer) {
    clearTimeout(authStore.logoutTimer);
  }

  // Proxy auth with custom logout subject to unknown external timeout
  if (logoutPage !== "/login" && authMethod === "proxy") {
    console.warn("idle timeout disabled with proxy auth and custom logout");
    return;
  }

  const timeout = expiresAt * 1000 - Date.now();
  authStore.setLogoutTimer(
    setSafeTimeout(() => {
      logout("inactivity");
    }, timeout)
  );
}

export async function refreshUser() {
  const me = await fetchMe();
  const authStore = useAuthStore();
  authStore.setUser(me.user);
  scheduleExpiry(me.expiresAt);
}

export async function validateLogin() {
  try {
    await refreshUser();
  } catch (error) {
    console.warn("No active session");
    throw error;
  }
}

export async function login(
  username: string,
  password: string,
  recaptcha: string
) {
  const data = { username, password, recaptcha };

  const res = await fetch(`${baseURL}/api/login`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (res.status !== 200) {
    const body = await res.text();
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }

  // The session cookie is HttpOnly: never read the token, just load the user.
  await refreshUser();
}

export async function renew() {
  const res = await fetch(`${baseURL}/api/renew`, {
    method: "POST",
    credentials: "same-origin",
  });

  if (res.status !== 200) {
    const body = await res.text();
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }

  await refreshUser();
}

export async function signup(username: string, password: string) {
  const data = { username, password };

  const res = await fetch(`${baseURL}/api/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (res.status !== 200) {
    const body = await res.text();
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export function logout(reason?: string) {
  // Revoke server-side first (best effort); the cookie dies with it.
  void fetch(`${baseURL}/api/logout`, {
    method: "DELETE",
    credentials: "same-origin",
  }).catch(() => {
    /* local logout proceeds regardless */
  });

  const authStore = useAuthStore();
  authStore.clearUser();

  if (noAuth) {
    window.location.reload();
  } else if (logoutPage !== "/login") {
    document.location.href = `${logoutPage}`;
  } else {
    if (typeof reason === "string" && reason.trim() !== "") {
      router.push({
        path: "/login",
        query: { "logout-reason": reason },
      });
    } else {
      router.push({
        path: "/login",
      });
    }
  }
}
