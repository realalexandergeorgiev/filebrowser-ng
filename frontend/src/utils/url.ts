export function removeLastDir(url: string) {
  const arr = url.split("/");
  if (arr.pop() === "") {
    arr.pop();
  }

  return arr.join("/");
}

// this function is taken from mozilla
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent#Examples
export function encodeRFC5987ValueChars(str: string) {
  return (
    encodeURIComponent(str)
      // The following creates the sequences %27 %28 %29 %2A (Note that
      // the valid encoding of "*" is %2A, which necessitates calling
      // toUpperCase() to properly encode). Although RFC3986 reserves "!",
      // RFC5987 does not, so we do not need to escape it.
      .replace(
        /['()*]/g,
        (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
      )
      // The following are not required for percent-encoding per RFC5987,
      // so we can allow for a little better readability over the wire: |`^
      .replace(/%(7C|60|5E)/g, (str, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      )
  );
}

export function encodePath(str: string) {
  return str
    .split("/")
    .map((v) => encodeURIComponent(v))
    .join("/");
}

// Only in-app paths are valid login redirect targets: anything else
// (protocol-relative URLs, non-strings from repeated params) falls back
// to the file browser root. router.push stays in-app, but a "//host"
// path would throw in pushState, so it is rejected too.
export function sanitizeRedirect(raw: unknown): string {
  if (typeof raw !== "string") {
    return "/files/";
  }
  if (!raw.startsWith("/") || raw.startsWith("//")) {
    return "/files/";
  }
  return raw;
}

export default {
  encodeRFC5987ValueChars,
  removeLastDir,
  encodePath,
  sanitizeRedirect,
};
