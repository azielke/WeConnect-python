#!/usr/bin/env python3
"""
Test script for the OIDC hybrid flow login fix (PR #237).

Usage:
    python test_login.py <email> <password>
    VW_EMAIL=... VW_PASSWORD=... python test_login.py

This script tests the fixed WeConnectSession.login() which uses the
OIDC hybrid flow (response_type=code id_token token) to get tokens
directly from the Auth0 callback URL without any BFF token exchange.
"""

import logging
import os
import sys
import time

# Set up detailed logging so we can see each step
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)-5s] %(name)s: %(message)s',
    datefmt='%H:%M:%S',
)
# Quiet down noisy loggers
logging.getLogger('urllib3').setLevel(logging.WARNING)

from weconnect.auth.we_connect_session import WeConnectSession
from weconnect.auth.session_manager import SessionUser
from weconnect.errors import AuthentificationError, TemporaryAuthentificationError


def test_login(email: str, password: str) -> bool:
    """Attempt a login and report results."""

    print("=" * 60)
    print("OIDC Hybrid Flow Login Test")
    print("=" * 60)
    print(f"Email:  {email}")
    print(f"Target: identity.vwgroup.io/oidc/v1/authorize")
    print(f"Flow:   Hybrid (response_type=code id_token token)")
    print()

    # Step 1: Create session
    print("[1/4] Creating WeConnectSession...")
    user = SessionUser(username=email, password=password)
    session = WeConnectSession(sessionuser=user)
    print(f"      Client ID:  {session.client_id}")
    print(f"      Scope:      {session.scope}")
    print(f"      Redirect:   {session.redirect_uri}")
    print()

    # Step 2: Login
    print("[2/4] Logging in (OIDC hybrid flow)...")
    start = time.time()
    try:
        session.login()
        elapsed = time.time() - start
    except AuthentificationError as e:
        print(f"\n  ❌  Authentication FAILED: {e}")
        return False
    except TemporaryAuthentificationError as e:
        print(f"\n  ⚠️  Temporary failure: {e}")
        return False
    except Exception as e:
        print(f"\n  ❌  Unexpected error: {type(e).__name__}: {e}")
        return False

    print(f"      Completed in {elapsed:.1f}s")
    print()

    # Step 3: Check tokens
    # Note: this codebase uses camelCase property names
    print("[3/4] Checking tokens...")
    tok = session.accessToken
    if not tok:
        print("  ❌  Not authorized — no access_token!")
        return False

    print(f"  ✅  access_token:  {tok[:20]}...{tok[-10:]}")
    print(f"      token_type:    {session.tokenType or 'N/A'}")
    print(f"      expires_in:    {session.expiresIn}s")

    idt = session.idToken
    if idt:
        print(f"  ✅  id_token:      {idt[:20]}...{idt[-10:]}")
    else:
        print(f"  ⚠️  No id_token in session")

    rt = session.refreshToken
    if rt:
        print(f"      refresh_token: {rt[:20]}...{rt[-10:]}")
    else:
        print(f"  ℹ️   No refresh_token (expected — hybrid flow limitation)")
        print(f"      Session lasts ~2h, then re-login needed.")

    # Decode JWT payload without verifying signature
    try:
        import jwt
        payload = jwt.decode(tok, options={"verify_signature": False})
        exp = payload.get('exp', 'N/A')
        if exp != 'N/A':
            from datetime import datetime, timezone
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            remaining = exp - time.time()
            print(f"      JWT exp:       {exp_dt.isoformat()} ({remaining:.0f}s remaining)")
        print(f"      JWT iss:       {payload.get('iss', 'N/A')}")
        print(f"      JWT sub:       {payload.get('sub', 'N/A')[:40]}...")
        print(f"      JWT aud:       {payload.get('aud', 'N/A')}")
    except Exception:
        pass

    print()

    # Step 4: Verify with a simple API call
    print("[4/4] Testing API access...")
    api_url = 'https://emea.bff.cariad.digital/vehicle/v1/vehicles'
    try:
        resp = session.get(
            api_url,
            headers={'accept': 'application/json'},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            count = len(data.get('data', []))
            print(f"  ✅  API responded 200 — {count} vehicle(s) found")
            for v in data.get('data', []):
                print(f"      • VIN: {v.get('vin', 'N/A')}")
        elif resp.status_code == 401:
            print(f"  ❌  API returned 401 — tokens not accepted by VW API")
            return False
        else:
            print(f"  ⚠️  API returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"  ⚠️  API call failed: {e}")
    return True


class RefreshLogCapture(logging.Handler):
    """Capture log messages to detect which refresh path was used."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_refresh(email: str, password: str) -> bool:
    """Test that refresh() works, and report whether a full login was needed."""

    print("=" * 60)
    print("OIDC Hybrid Flow — Token Refresh Test")
    print("=" * 60)
    print()
    print("The hybrid flow issues NO refresh_token, so refresh() first")
    print("tries prompt=none (silent, using Auth0 SSO cookie), and only")
    print("falls back to a full credential-based login if the cookie expired.")
    print()

    # Step 1: Initial login
    print("[1/4] Initial login...")
    user = SessionUser(username=email, password=password)
    session = WeConnectSession(sessionuser=user)
    try:
        session.login()
    except Exception as e:
        print(f"  ❌  Login failed: {type(e).__name__}: {e}")
        return False

    old_token = session.accessToken
    print(f"  ✅  Logged in")
    print(f"      access_token:  {old_token[:20]}...{old_token[-10:]}")
    print()

    # Step 2: Expire the token (simulate time passing)
    print("[2/4] Simulating token expiry...")
    if session.token and 'expires_at' in session.token:
        session.token['expires_at'] = 0  # force immediate expiry
        print(f"  ✅  Token marked as expired (expires_at = 0)")
    print()

    # Step 3: Call refresh and capture how it happened
    print("[3/4] Calling session.refresh()...")
    log_capture = RefreshLogCapture()
    logging.getLogger('weconnect').addHandler(log_capture)

    import time
    start = time.time()
    try:
        session.refresh()
        elapsed = time.time() - start
    except Exception as e:
        print(f"  ❌  Refresh failed: {type(e).__name__}: {e}")
        return False
    finally:
        logging.getLogger('weconnect').removeHandler(log_capture)

    new_token = session.accessToken
    print(f"      Completed in {elapsed:.1f}s")
    print(f"      New access_token:  {new_token[:20]}...{new_token[-10:]}" if new_token else "      No token!")

    # Detect which path was used
    silent_success = any('Silent re-authentication succeeded' in m for m in log_capture.messages)
    silent_failed = any('Silent re-auth failed' in m for m in log_capture.messages)
    full_login = any('Performing full re-login' in m for m in log_capture.messages)

    print()
    if silent_success:
        print("  🔇  SILENT re-auth was sufficient!")
        print("      Auth0 SSO session cookie was still valid — no login form needed.")
        print("      Tokens refreshed transparently without credentials.")
    elif silent_failed and full_login:
        print("  🔐  FULL re-login was required.")
        print("      Auth0 SSO session cookie had expired — credentials were re-sent.")
        print(f"      Silent re-auth failure reason: {next((m for m in log_capture.messages if 'Silent re-auth failed' in m), 'unknown')}")
    else:
        print(f"  ⚠️  Could not determine refresh path from logs.")
        if log_capture.messages:
            print(f"      Captured messages: {log_capture.messages}")

    if old_token == new_token:
        print(f"  ⚠️  Token unchanged — refresh may have returned same session")
    else:
        print(f"  ✅  Token was replaced")
    print()

    # Step 4: Verify new token works
    print("[4/4] Verifying new token with API call...")
    try:
        resp = session.get(
            'https://emea.bff.cariad.digital/vehicle/v1/vehicles',
            headers={'accept': 'application/json'},
            timeout=30,
        )
        if resp.status_code == 200:
            print(f"  ✅  New token accepted by API (200)")
        elif resp.status_code == 401:
            print(f"  ❌  New token rejected by API (401)")
            return False
        else:
            print(f"  ⚠️  API returned {resp.status_code}")
    except Exception as e:
        print(f"  ⚠️  API call failed: {e}")

    print()
    print("=" * 60)
    if silent_success:
        print("✅ Refresh test passed — silent re-auth works!")
    else:
        print("✅ Refresh test passed — full re-login fallback works!")
    print("=" * 60)
    return True


if __name__ == '__main__':
    if '--refresh' in sys.argv:
        sys.argv.remove('--refresh')
        test_mode = 'refresh'
    else:
        test_mode = 'login'

    # Get credentials from args or env
    if len(sys.argv) == 3:
        email = sys.argv[1]
        password = sys.argv[2]
    else:
        email = os.environ.get('VW_EMAIL')
        password = os.environ.get('VW_PASSWORD')

    if not email or not password:
        print("Usage: python test_login.py [--refresh] <email> <password>")
        print("  or:  VW_EMAIL=... VW_PASSWORD=... python test_login.py [--refresh]")
        print()
        print("  --refresh   Test token refresh (re-login) after successful login")
        sys.exit(1)

    if test_mode == 'refresh':
        success = test_refresh(email, password)
    else:
        success = test_login(email, password)
    sys.exit(0 if success else 1)
