#!/usr/bin/env python3
"""
================================================================================
 APERO TOKEN REFRESH (Phase 2)  --  POST /api/v1/auth
================================================================================
 Exchanges the stored refresh_token for a fresh access_token + NEW
 refresh_token (Apero rotates the refresh token on every call).

 Reads :  APERO_REFRESH_TOKEN   (env -- from GitHub secret)
 Writes:  GITHUB_ENV            APERO_BEARER_TOKEN=<new access token>
          GITHUB_OUTPUT         new_refresh_token=<new refresh token>
 Both values are masked via ::add-mask:: BEFORE being written, so they can
 never appear in any log line.

 Explicit-fail rules:
   * non-200/201 response  -> exit 1 with instructions to re-seed the secret
   * missing token fields  -> exit 1 (API shape changed)
 The caller (workflow) MUST persist new_refresh_token back to the GitHub
 secret IMMEDIATELY -- before the data pull -- or the rotation chain breaks.
================================================================================
"""
import json
import time
import os
import sys

import requests

AUTH_URL = "https://mktpro.aperogroup.ai/api/v1/auth"
TIMEOUT = 30


def fail(msg: str) -> None:
    print(f"\n🚨 TOKEN REFRESH FAILED: {msg}", file=sys.stderr)
    print("   If the refresh token has expired (>24h since last run) or the\n"
          "   chain broke, re-seed it: log in to mktpro.aperogroup.ai, grab the\n"
          "   refresh_token cookie from DevTools -> Application -> Cookies, and\n"
          "   update the APERO_REFRESH_TOKEN GitHub secret.", file=sys.stderr)
    sys.exit(1)


def mask(value: str) -> None:
    """Tell the Actions runner to censor this value in ALL future log output."""
    print(f"::add-mask::{value}")


def main() -> None:
    refresh_token = os.environ.get("APERO_REFRESH_TOKEN", "").strip()
    if not refresh_token:
        fail("APERO_REFRESH_TOKEN env var is empty -- secret not set?")
    mask(refresh_token)  # never let even the old token print

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://mktpro.aperogroup.ai",
        "Referer": "https://mktpro.aperogroup.ai/partner-report/business",
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/148.0.0.0 Safari/537.36"),
    }
    # Confirmed from DevTools capture: payload key is camelCase "refreshToken".
    # We send both spellings defensively -- servers ignore unknown fields.
    body = {"refreshToken": refresh_token, "refresh_token": refresh_token}

    # Retry transient failures (5xx / network) with exponential backoff.
    # NEVER retry 4xx: with rotating tokens, blind retries on auth errors
    # could damage the chain. 503s from istio-envoy are common cold-start
    # hiccups on Apero's side and resolve within seconds.
    attempts, delay = 4, 5
    resp = None
    for i in range(1, attempts + 1):
        try:
            resp = requests.post(AUTH_URL, json=body, headers=headers,
                                 timeout=TIMEOUT)
        except requests.RequestException as exc:
            if i == attempts:
                fail(f"network error after {attempts} attempts: {exc}")
            print(f"⚠️  attempt {i}/{attempts} network error ({exc}); "
                  f"retrying in {delay}s")
            time.sleep(delay)
            delay *= 2
            continue
        if resp.status_code >= 500:
            if i == attempts:
                fail(f"HTTP {resp.status_code} after {attempts} attempts: "
                     f"{resp.text[:300]}")
            print(f"⚠️  attempt {i}/{attempts} got HTTP {resp.status_code} "
                  f"(Apero server-side); retrying in {delay}s")
            time.sleep(delay)
            delay *= 2
            continue
        break

    if resp.status_code not in (200, 201):
        fail(f"HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        data = resp.json()
    except ValueError:
        fail(f"non-JSON response: {resp.text[:300]}")

    # Apero wraps most responses in dataSource -- handle wrapped AND flat.
    payload = data.get("dataSource", data)
    if isinstance(payload, list):           # defensive: some endpoints use lists
        payload = payload[0] if payload else {}

    access = payload.get("access_token") or payload.get("accessToken")
    new_refresh = payload.get("refresh_token") or payload.get("refreshToken")

    if not access:
        fail(f"no access_token in response; keys seen: {list(payload)[:10]}")
    if not new_refresh:
        fail(f"no refresh_token in response (rotation expected); "
             f"keys seen: {list(payload)[:10]}")

    mask(access)
    mask(new_refresh)

    github_env = os.environ.get("GITHUB_ENV")
    github_out = os.environ.get("GITHUB_OUTPUT")
    if not github_env or not github_out:
        fail("GITHUB_ENV / GITHUB_OUTPUT not set -- not running inside Actions?")

    with open(github_env, "a") as f:
        f.write(f"APERO_BEARER_TOKEN={access}\n")
    with open(github_out, "a") as f:
        f.write(f"new_refresh_token={new_refresh}\n")

    who = payload.get("name") or payload.get("email") or "unknown"
    print(f"✅ token refreshed (account: {who}); access token exported, "
          f"new refresh token staged for secret rotation")


if __name__ == "__main__":
    main()
