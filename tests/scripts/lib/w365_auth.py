# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Private stdout token transport for run_w365_command_manual.ps1."""

import argparse
import base64
import contextlib
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
import uuid


RESOURCE = "274133f7-12bb-4bfb-ae3b-bd446b7e8a75"
SCOPES = [f"{RESOURCE}/.default"]
DELEGATED = {"Computer.Get", "Computer.See", "Computer.Do", "Computer.Control"}


class AuthError(Exception):
    """A fixed, safe diagnostic, never an MSAL response or exception body."""


def guid(value):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise AuthError("invalid_identity_guid") from None
    if str(parsed) != str(value).lower() or parsed.int == 0:
        raise AuthError("invalid_identity_guid")
    return str(parsed)


def verify_token(token, tenant, client, expected_oid=None, minimum_validity=300):
    # These are sanity checks on MSAL's result, not signature validation.
    try:
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
            raise ValueError()
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError()
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(claims, dict):
            raise ValueError()
        oid = guid(claims.get("oid"))
        callers = [claims[key] for key in ("azp", "appid") if key in claims]
        if (
            guid(claims.get("tid")) != tenant
            or not callers
            or any(guid(caller) != client for caller in callers)
            or claims.get("aud") not in (RESOURCE, f"api://{RESOURCE}")
            or (expected_oid and oid != expected_oid)
            or not isinstance(claims.get("scp"), str)
            or not DELEGATED.issubset(set(claims["scp"].split()))
            or type(claims.get("exp")) is not int
            or claims["exp"] - time.time() < minimum_validity
            or ("nbf" in claims and (
                type(claims["nbf"]) is not int or claims["nbf"] > time.time() + 60
            ))
        ):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AuthError):
        raise AuthError("token_identity_audience_scopes_or_lifetime_mismatch") from None
    return {"accessToken": token, "userObjectId": oid, "expiresOn": claims["exp"]}


def acquire(app, args):
    accounts = [
        account for account in app.get_accounts()
        if account.get("realm", "").lower() == args.tenant_id
        and account.get("environment", "").lower() in (
            "login.microsoftonline.com", "login.windows.net"
        )
        and (not args.expected_user_object_id
             or account.get("local_account_id", "").lower() == args.expected_user_object_id)
        and (not args.login_hint
             or account.get("username", "").lower() == args.login_hint.lower())
    ]
    result = None
    if not args.force_sign_in and len(accounts) == 1:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
    if not result or "access_token" not in result:
        if args.silent_only:
            raise AuthError("cleanup_silent_renewal_requires_interaction")
        print("Opening the system browser; existing MFA/consent policy applies.", file=sys.stderr)
        result = app.acquire_token_interactive(
            scopes=SCOPES,
            login_hint=args.login_hint,
            prompt="select_account",
            timeout=240,
            port=0,
        )
    if not isinstance(result, dict) or not result.get("access_token"):
        code = result.get("error", "") if isinstance(result, dict) else ""
        safe = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_]{1,80}", code) else "no_access_token"
        raise AuthError(f"sign_in_failed_{safe}")
    return verify_token(
        result["access_token"], args.tenant_id, args.client_id,
        args.expected_user_object_id, args.minimum_validity,
    )


def cache_path(tenant, client):
    if sys.platform != "win32" or not os.environ.get("LOCALAPPDATA"):
        raise AuthError("windows_localappdata_required_for_dpapi_cache")
    return Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "MXC" / "w365-manual-auth" / f"{tenant}_{client}.bin"


def acquire_persisted(args):
    try:
        import msal
        from msal_extensions import CrossPlatLock, FilePersistenceWithDataProtection, PersistedTokenCache
    except ImportError:
        raise AuthError("install_prerequisites_python_-m_pip_install_msal_msal-extensions") from None
    location = cache_path(args.tenant_id, args.client_id)
    location.parent.mkdir(parents=True, exist_ok=True)
    # Serialize account selection and refresh as well as MSAL's individual writes.
    # Separate locks avoid recursively acquiring PersistedTokenCache's write lock.
    with CrossPlatLock(str(location) + ".operation.lock"):
        persistence = FilePersistenceWithDataProtection(str(location))
        if not persistence.is_encrypted:
            raise AuthError("encrypted_cache_required")
        cache = PersistedTokenCache(persistence, lock_location=str(location) + ".lockfile")
        app = msal.PublicClientApplication(
            args.client_id,
            authority=f"https://login.microsoftonline.com/{args.tenant_id}",
            token_cache=cache,
            enable_broker_on_windows=False,
        )
        result = acquire(app, args)
    result["cachePath"] = str(location)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--login-hint")
    parser.add_argument("--expected-user-object-id")
    parser.add_argument("--force-sign-in", action="store_true")
    parser.add_argument("--silent-only", action="store_true")
    parser.add_argument("--minimum-validity", type=int, default=300)
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    try:
        args.tenant_id = guid(args.tenant_id)
        args.client_id = guid(args.client_id)
        if args.expected_user_object_id:
            args.expected_user_object_id = guid(args.expected_user_object_id)
        if args.minimum_validity < 60 or (args.force_sign_in and args.silent_only):
            raise AuthError("invalid_auth_options")
        # A dependency must never accidentally print a token/response to the console.
        with contextlib.redirect_stdout(sys.stderr):
            result = acquire_persisted(args)
        sys.stdout.write(json.dumps(result))
        return 0
    except AuthError as error:
        print(f"W365_AUTH_ERROR:{error}", file=sys.stderr)
        return 2
    except Exception as error:
        # Terminal boundary: report the failure, without leaking cache contents,
        # OAuth error descriptions, HTTP bodies or exception arguments.
        print(f"W365_AUTH_ERROR:cache_or_auth_failure_{type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
