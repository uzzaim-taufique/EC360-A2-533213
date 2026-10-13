"""Unit tests for QM-5 registration workflow. Run: py -m unittest -v"""
import time
import unittest

import auth_service as svc


class TestRegistration(unittest.TestCase):
    def setUp(self):
        svc._users.clear()

    def test_successful_registration_returns_201_pending(self):
        status, body = svc.register_user("alice@example.com", "StrongPass123!")
        self.assertEqual(status, 201)
        self.assertEqual(body["status"], "pending_verification")
        self.assertFalse(svc._users["alice@example.com"]["verified"])

    def test_duplicate_registration_returns_409(self):
        svc.register_user("alice@example.com", "StrongPass123!")
        status, body = svc.register_user("alice@example.com", "AnotherPass456!")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "An account with this email already exists")

    def test_short_password_rejected(self):
        status, _ = svc.register_user("bob@example.com", "short")
        self.assertEqual(status, 400)

    def test_password_is_hashed_not_plaintext(self):
        svc.register_user("carol@example.com", "StrongPass123!")
        stored = svc._users["carol@example.com"]["password"]
        self.assertNotIn("StrongPass123!", stored)
        self.assertTrue(svc.verify_password("StrongPass123!", stored))

    def test_valid_token_verifies_account(self):
        _, body = svc.register_user("dave@example.com", "StrongPass123!")
        status, _ = svc.verify_email(body["verification_token"])
        self.assertEqual(status, 200)
        self.assertTrue(svc._users["dave@example.com"]["verified"])

    def test_expired_token_rejected(self):
        svc.register_user("erin@example.com", "StrongPass123!")
        old = svc.make_verification_token("erin@example.com", time.time() - 25 * 3600)
        status, _ = svc.verify_email(old)
        self.assertEqual(status, 410)


if __name__ == "__main__":
    unittest.main()