# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Manual, offline authentication regressions. Never opens a real user cache."""

import argparse
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("w365_auth", Path(__file__).parent / "lib" / "w365_auth.py")
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)
TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
OWNER = "33333333-3333-3333-3333-333333333333"
OTHER = "44444444-4444-4444-4444-444444444444"


def token(**overrides):
    claims = {
        "aud": auth.RESOURCE, "tid": TENANT, "oid": OWNER, "azp": CLIENT,
        "scp": " ".join(sorted(auth.DELEGATED)), "exp": int(time.time()) + 3600,
    }
    claims.update(overrides)
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"synthetic.{encoded}.not-a-real-signature"


def options(**overrides):
    args = dict(tenant_id=TENANT, client_id=CLIENT, login_hint=None,
                expected_user_object_id=None, force_sign_in=False,
                silent_only=False, minimum_validity=300)
    args.update(overrides)
    return argparse.Namespace(**args)


def account(**overrides):
    value = dict(realm=TENANT, environment="login.windows.net",
                 local_account_id=OWNER, username="synthetic@example.invalid")
    value.update(overrides)
    return value


def app(accounts=None, silent=None, interactive=None):
    value = Mock()
    value.get_accounts.return_value = [account()] if accounts is None else accounts
    value.acquire_token_silent.return_value = {"access_token": token()} if silent is None else silent
    value.acquire_token_interactive.return_value = {"access_token": token()} if interactive is None else interactive
    return value


class AuthenticationTests(unittest.TestCase):
    def test_silent_hit_and_refresh_return_same_verified_identity(self):
        for refreshed in (False, True):
            with self.subTest(refreshed=refreshed):
                client = app(silent={"access_token": token(), "token_source": "identity_provider" if refreshed else "cache"})
                result = auth.acquire(client, options())
                self.assertEqual(result["userObjectId"], OWNER)
                client.acquire_token_silent.assert_called_once_with(auth.SCOPES, account=account())
                client.acquire_token_interactive.assert_not_called()

    def test_missing_or_interaction_required_uses_browser_fixed_scope(self):
        for accounts, silent in (([], {}), ([account()], {}), ([account()], {"error": "interaction_required"})):
            with self.subTest(accounts=accounts, silent=silent):
                client = app(accounts, silent)
                auth.acquire(client, options())
                kwargs = client.acquire_token_interactive.call_args.kwargs
                self.assertEqual(kwargs["scopes"], [f"{auth.RESOURCE}/.default"])
                self.assertEqual(kwargs["prompt"], "select_account")
                self.assertEqual(kwargs["port"], 0)
                self.assertEqual(kwargs["timeout"], 240)

    def test_force_sign_in_bypasses_silent_but_not_cache_loading(self):
        client = app()
        auth.acquire(client, options(force_sign_in=True))
        client.get_accounts.assert_called_once()
        client.acquire_token_silent.assert_not_called()
        client.acquire_token_interactive.assert_called_once()

    def test_ambiguous_and_foreign_accounts_never_silently_selected(self):
        for accounts in (
            [account(), account(local_account_id=OTHER, username="other@example.invalid")],
            [account(realm=OTHER)], [account(environment="untrusted.invalid")],
        ):
            with self.subTest(accounts=accounts):
                client = app(accounts)
                auth.acquire(client, options())
                client.acquire_token_silent.assert_not_called()
                client.acquire_token_interactive.assert_called_once()

    def test_expected_oid_and_hint_filter_selection_not_identity(self):
        client = app([account(), account(local_account_id=OTHER, username="other@example.invalid")])
        auth.acquire(client, options(expected_user_object_id=OWNER))
        self.assertEqual(client.acquire_token_silent.call_args.kwargs["account"]["local_account_id"], OWNER)
        client = app([account()], interactive={"access_token": token(oid=OTHER)})
        with self.assertRaises(auth.AuthError):
            auth.acquire(client, options(login_hint="other@example.invalid", expected_user_object_id=OWNER))
        client.acquire_token_silent.assert_not_called()
        self.assertEqual(client.acquire_token_interactive.call_args.kwargs["login_hint"], "other@example.invalid")

    def test_cleanup_never_opens_browser(self):
        for accounts, silent in (([], {}), ([account()], {}), ([account(), account()], {})):
            client = app(accounts, silent)
            with self.assertRaisesRegex(auth.AuthError, "cleanup_silent"):
                auth.acquire(client, options(silent_only=True))
            client.acquire_token_interactive.assert_not_called()

    def test_token_guards(self):
        changes = [
            {"aud": "https://unapproved.invalid"}, {"aud": OTHER}, {"tid": OTHER},
            {"azp": OTHER}, {"appid": OTHER}, {"oid": OTHER}, {"oid": None},
            {"scp": "Computer.Get Computer.See Computer.Do"}, {"scp": ["Computer.Control"]},
            {"exp": int(time.time()) + 299}, {"exp": str(int(time.time()) + 3600)},
            {"nbf": int(time.time()) + 3600}, {"tid": None}, {"azp": None},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(auth.AuthError):
                auth.verify_token(token(**change), TENANT, CLIENT, OWNER)
        for malformed in ("not-a-jwt", "a.??.c", "a.W10.c", "", None):
            with self.subTest(malformed=malformed), self.assertRaises(auth.AuthError):
                auth.verify_token(malformed, TENANT, CLIENT)
        self.assertEqual(auth.verify_token(token(aud=f"api://{auth.RESOURCE}"), TENANT, CLIENT)["userObjectId"], OWNER)
        self.assertEqual(auth.verify_token(token(azp=CLIENT, appid=CLIENT), TENANT, CLIENT)["userObjectId"], OWNER)
        self.assertEqual(auth.verify_token(token(azp=CLIENT.upper()), TENANT, CLIENT)["userObjectId"], OWNER)

    def test_consent_error_does_not_change_permissions_or_print_body(self):
        client = app([], interactive={"error": "consent_required", "error_description": "SYNTHETIC_SECRET"})
        with self.assertRaisesRegex(auth.AuthError, "^sign_in_failed_consent_required$"):
            auth.acquire(client, options())
        self.assertEqual(client.acquire_token_interactive.call_count, 1)

    def test_cache_errors_are_terminal_sanitized_and_never_fallback(self):
        for failure in ("lock", "decrypt", "save"):
            with self.subTest(failure=failure), patch.object(
                auth, "acquire_persisted", side_effect=RuntimeError("SYNTHETIC_SECRET_" + failure)
            ), contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                status = auth.main(["--tenant-id", TENANT, "--client-id", CLIENT])
                self.assertEqual(status, 2)
                self.assertEqual(out.getvalue(), "")
                self.assertNotIn("SYNTHETIC_SECRET", err.getvalue())
                self.assertIn("cache_or_auth_failure_RuntimeError", err.getvalue())

    def test_cache_binding_encryption_and_lock_failures(self):
        with tempfile.TemporaryDirectory(prefix="mxc-w365-auth-unit-") as root:
            persistence = Mock(is_encrypted=True)
            extension = types.ModuleType("msal_extensions")
            extension.CrossPlatLock = Mock(return_value=contextlib.nullcontext())
            extension.FilePersistenceWithDataProtection = Mock(return_value=persistence)
            extension.PersistedTokenCache = Mock()
            msal = types.ModuleType("msal")
            client = app()
            msal.PublicClientApplication = Mock(return_value=client)
            with patch.dict(sys.modules, msal=msal, msal_extensions=extension), patch.object(
                auth.sys, "platform", "win32"
            ), patch.dict(os.environ, LOCALAPPDATA=root):
                result = auth.acquire_persisted(options())
                expected = str(Path(root) / "Microsoft" / "MXC" / "w365-manual-auth" / f"{TENANT}_{CLIENT}.bin")
                self.assertEqual(result["cachePath"], expected)
                extension.FilePersistenceWithDataProtection.assert_called_once_with(expected)
                extension.CrossPlatLock.assert_called_once_with(expected + ".operation.lock")
                self.assertEqual(msal.PublicClientApplication.call_args.kwargs["authority"],
                                 f"https://login.microsoftonline.com/{TENANT}")
                self.assertFalse(msal.PublicClientApplication.call_args.kwargs["enable_broker_on_windows"])
                persistence.is_encrypted = False
                with self.assertRaisesRegex(auth.AuthError, "encrypted_cache_required"):
                    auth.acquire_persisted(options())
                persistence.is_encrypted = True
                for target in (extension.CrossPlatLock, extension.FilePersistenceWithDataProtection,
                               extension.PersistedTokenCache):
                    target.side_effect = OSError("synthetic_cache_failure")
                    with self.assertRaises(OSError):
                        auth.acquire_persisted(options())
                    target.side_effect = None
                client.acquire_token_silent.side_effect = OSError("synthetic_read_or_save_failure")
                with self.assertRaises(OSError):
                    auth.acquire_persisted(options())
                client.acquire_token_interactive.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "DPAPI requires Windows")
class ProtectedPersistenceTests(unittest.TestCase):
    def test_dpapi_persists_synthetic_cache_across_fresh_processes(self):
        from msal_extensions import FilePersistenceWithDataProtection, PersistedTokenCache
        import msal
        with tempfile.TemporaryDirectory(prefix="mxc-w365-dpapi-fixture-") as root:
            path = str(Path(root) / "synthetic.bin")
            persistence = FilePersistenceWithDataProtection(path)
            self.assertTrue(persistence.is_encrypted)
            cache = PersistedTokenCache(persistence)
            cache.modify(msal.TokenCache.CredentialType.ACCOUNT, {}, {
                "home_account_id": "synthetic.nonsecret", "environment": "example.invalid",
                "realm": TENANT, "local_account_id": OWNER, "username": "synthetic@example.invalid",
            })
            self.assertNotIn(b"synthetic@example.invalid", Path(path).read_bytes())
            script = (
                "import sys,msal; from msal_extensions import FilePersistenceWithDataProtection,PersistedTokenCache;"
                "c=PersistedTokenCache(FilePersistenceWithDataProtection(sys.argv[1]));"
                "a=c.find(msal.TokenCache.CredentialType.ACCOUNT);"
                "assert len(a)==1 and a[0]['username']=='synthetic@example.invalid';print('protected fixture read')"
            )
            result = subprocess.run([sys.executable, "-c", script, path], capture_output=True, text=True, timeout=15, check=True)
            self.assertEqual(result.stdout.strip(), "protected fixture read")
            Path(path).write_bytes(b"synthetic_invalid_ciphertext")
            with self.assertRaises(Exception):
                FilePersistenceWithDataProtection(path).load()

    def test_real_cache_lock_serializes_fresh_processes_and_fails_explicitly(self):
        from msal_extensions import CrossPlatLock
        with tempfile.TemporaryDirectory(prefix="mxc-w365-lock-fixture-") as root:
            lock = str(Path(root) / "synthetic.lock")
            script = (
                "import sys;from msal_extensions import CrossPlatLock;"
                "\nwith CrossPlatLock(sys.argv[1]): print('acquired')"
            )
            child = None
            try:
                with CrossPlatLock(lock):
                    child = subprocess.Popen([sys.executable, "-c", script, lock],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    time.sleep(0.6)
                    self.assertIsNone(child.poll())
                out, err = child.communicate(timeout=10)
            finally:
                if child and child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)
            self.assertEqual((child.returncode, out.strip(), err), (0, "acquired", ""))
            with CrossPlatLock(lock):
                result = subprocess.run([sys.executable, "-c", script, lock], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("LockError", result.stderr)


if __name__ == "__main__":
    unittest.main()
