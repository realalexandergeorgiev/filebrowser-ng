import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/utils/auth", () => ({ renew: vi.fn(), logout: vi.fn() }));
vi.mock("@/utils/constants", () => ({ baseURL: "" }));

import { fetchURL } from "@/api/utils";
import { renew, logout } from "@/utils/auth";

function response(status: number, headers: Record<string, string> = {}) {
  return new Response("{}", { status, headers });
}

describe("fetchURL session transport", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("sends same-origin credentials and no X-Auth header", async () => {
    const seen: RequestInit[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        seen.push(init);
        return response(200);
      })
    );

    await fetchURL("/api/resources/", { headers: { "X-Custom": "1" } });

    expect(seen).toHaveLength(1);
    expect(seen[0].credentials).toBe("same-origin");
    const headers = seen[0].headers as Record<string, string>;
    expect(headers["X-Auth"]).toBeUndefined();
    expect(headers["X-Custom"]).toBe("1");
  });

  it("renews on X-Renew-Token without sending a token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response(200, { "X-Renew-Token": "true" }))
    );

    await fetchURL("/api/resources/", {});
    expect(renew).toHaveBeenCalledTimes(1);
    expect(renew).toHaveBeenCalledWith();
  });

  it("logs out on 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response(401))
    );

    await expect(fetchURL("/api/resources/", {})).rejects.toMatchObject({
      status: 401,
    });
    expect(logout).toHaveBeenCalledTimes(1);
  });
});
