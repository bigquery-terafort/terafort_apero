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
                       "Chrome/149.0.0.0 Safari/537.36"),
        # ---- THE FIX ----
        # Confirmed via live DevTools capture (2026-07-09): the browser
        # attaches the refresh token as a Cookie header on this exact call,
        # in addition to the JSON body. The API appears to require it --
        # without this header, requests 401 even with a fully valid token.
        "Cookie": f"refresh_token={refresh_token}",
    }
    # Confirmed from DevTools capture (Payload tab): the browser sends
    # ONLY "refreshToken" (camelCase) in the body -- no snake_case variant.
    # We still send both defensively; servers ignore unknown fields, and
    # this protects us if the API ever accepts either spelling.
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

    # 201 Created is what the real API returns on success (confirmed via
    # DevTools: Status Code 201 Created) -- 200 kept too, just in case.
    if resp.status_code not in (200, 201):
        fail(f"HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        data = resp.json()
    except ValueError:
        fail(f"non-JSON response: {resp.text[:300]}")

    # Confirmed via DevTools Response tab: shape is
    #   {"dataSource": {"name": ..., "accessToken": ..., "refreshToken": ...}}
    # i.e. camelCase, wrapped in dataSource (not a list here). Handle wrapped
    # AND flat, and both camelCase/snake_case, to survive minor API drift.
    payload = data.get("dataSource", data)
    if isinstance(payload, list):           # defensive: some endpoints use lists
        payload = payload[0] if payload else {}

    access = payload.get("accessToken") or payload.get("access_token")
    new_refresh = payload.get("refreshToken") or payload.get("refresh_token")

    if not access:
        fail(f"no accessToken in response; keys seen: {list(payload)[:10]}")
    if not new_refresh:
        fail(f"no refreshToken in response (rotation expected); "
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




























































































































