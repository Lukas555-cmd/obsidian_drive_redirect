/**
 * OAuth 2.0 PKCE callback bridge for Obsidian Drive Vault Sync.
 *
 * Receives the Google OAuth redirect on HTTPS and forwards only allowlisted
 * parameters to obsidian://drive-vault-sync-auth. Never logs secrets or tokens.
 */

export const PROTOCOL_ACTION = "drive-vault-sync-auth";

export const ALLOWED_PARAMS = Object.freeze([
  "code",
  "state",
  "scope",
  "error",
  "error_description",
]);

/**
 * Builds the obsidian:// callback URL using only allowlisted non-empty params.
 * @param {URLSearchParams} params
 * @returns {string}
 */
function buildTargetUrl(params) {
  const filtered = new URLSearchParams();
  for (const key of ALLOWED_PARAMS) {
    const value = params.get(key);
    if (value !== null && value !== "") {
      filtered.set(key, value);
    }
  }
  const query = filtered.toString();
  return query
    ? `obsidian://${PROTOCOL_ACTION}?${query}`
    : `obsidian://${PROTOCOL_ACTION}`;
}

/**
 * Parses an OAuth callback query string and returns a structured result.
 * @param {string} search
 */
export function parseOAuthCallback(search) {
  const params = new URLSearchParams(search);
  const error = params.get("error");

  if (error !== null && error !== "") {
    return {
      status: "error",
      error,
      errorDescription: params.get("error_description") ?? "",
      targetUrl: buildTargetUrl(params),
    };
  }

  const code = params.get("code");
  const state = params.get("state");

  if (code !== null && code !== "") {
    if (state === null || state === "") {
      return {
        status: "invalid",
        reason: "missing-state",
        targetUrl: null,
      };
    }

    return {
      status: "success",
      targetUrl: buildTargetUrl(params),
    };
  }

  return {
    status: "idle",
    targetUrl: null,
  };
}

/**
 * Scrubs sensitive OAuth query parameters from the browser address bar/history.
 * @param {Window} win
 */
function scrubHistory(win) {
  try {
    if (win.history && typeof win.history.replaceState === "function") {
      win.history.replaceState(null, "", win.location.pathname || "/");
    }
  } catch {
    // Ignore if history API is restricted in a custom environment.
  }
}

/**
 * Initializes the redirect page DOM and triggers the Obsidian deep-link.
 * @param {Document} [doc]
 * @param {Window} [win]
 */
export function initRedirectPage(doc = document, win = window) {
  const result = parseOAuthCallback(win.location?.search ?? "");

  const titleEl = doc.getElementById("status-title");
  const messageEl = doc.getElementById("status-message");
  const openBtn = doc.getElementById("open-obsidian");
  const errorBox = doc.getElementById("error-box");

  if (result.status === "success") {
    if (titleEl) titleEl.textContent = "Sign-in complete";
    if (messageEl) {
      messageEl.textContent =
        "Returning you to Obsidian. If Obsidian does not open automatically, click the button below.";
    }
    if (errorBox) errorBox.hidden = true;
    if (openBtn) {
      openBtn.setAttribute("href", result.targetUrl);
      openBtn.hidden = false;
    }
    scrubHistory(win);
    win.location.replace(result.targetUrl);
    return result;
  }

  if (result.status === "error") {
    if (titleEl) titleEl.textContent = "Google sign-in did not complete";
    if (messageEl) {
      messageEl.textContent =
        "Google returned an authorization error. You can return to Obsidian to cancel or try again.";
    }
    if (errorBox) {
      const detail = result.errorDescription
        ? `${result.error}: ${result.errorDescription}`
        : result.error;
      errorBox.textContent = detail;
      errorBox.hidden = false;
    }
    if (openBtn) {
      openBtn.setAttribute("href", result.targetUrl);
      openBtn.hidden = false;
    }
    scrubHistory(win);
    return result;
  }

  if (result.status === "invalid") {
    if (titleEl) titleEl.textContent = "Invalid sign-in callback";
    if (messageEl) {
      messageEl.textContent =
        "This callback is missing the required security state parameter. Please return to Obsidian and start Google Drive sign-in again.";
    }
    if (errorBox) {
      errorBox.textContent = "Missing required 'state' parameter.";
      errorBox.hidden = false;
    }
    if (openBtn) openBtn.hidden = true;
    return result;
  }

  // status === "idle"
  if (titleEl) titleEl.textContent = "Obsidian Drive Vault Sync";
  if (messageEl) {
    messageEl.textContent =
      "This page completes Google Drive sign-in for the Obsidian Drive Vault Sync plugin. Start sign-in from Obsidian settings.";
  }
  if (errorBox) errorBox.hidden = true;
  if (openBtn) openBtn.hidden = true;
  return result;
}

if (typeof document !== "undefined" && typeof window !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => initRedirectPage());
  } else {
    initRedirectPage();
  }
}
