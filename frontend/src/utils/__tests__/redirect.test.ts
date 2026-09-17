import { describe, it, expect } from "vitest";
import { sanitizeRedirect } from "../url";

describe("sanitizeRedirect", () => {
  it("keeps in-app paths", () => {
    expect(sanitizeRedirect("/files/")).toBe("/files/");
    expect(sanitizeRedirect("/share/abc123")).toBe("/share/abc123");
    expect(sanitizeRedirect("/files/a:b")).toBe("/files/a:b");
  });

  it("falls back for external or exotic targets", () => {
    expect(sanitizeRedirect("//evil.com/x")).toBe("/files/");
    expect(sanitizeRedirect("https://evil.com/")).toBe("/files/");
    expect(sanitizeRedirect("javascript:alert(1)")).toBe("/files/");
    expect(sanitizeRedirect("")).toBe("/files/");
  });

  it("falls back for non-strings (repeated params)", () => {
    expect(sanitizeRedirect(["/files/", "/evil"])).toBe("/files/");
    expect(sanitizeRedirect(undefined)).toBe("/files/");
    expect(sanitizeRedirect(null)).toBe("/files/");
  });
});
