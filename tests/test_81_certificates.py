import os
from os import remove
import tempfile
import time


__author__ = "haho0032"
import unittest

from saml2.cert import OpenSSLWrapper
from saml2.sigver import CertHandler


class TestGenerateCertificates(unittest.TestCase):
    def test_validate_with_root_cert(self):

        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }

        cert_info = {
            "cn": "asdfgh",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        osw = OpenSSLWrapper()

        ca_cert, ca_key = osw.create_certificate(
            cert_info_ca,
            request=False,
            write_to_file=True,
            cert_dir=f"{os.path.dirname(os.path.abspath(__file__))}/pki",
        )

        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)

        ca_cert_str = osw.read_str_from_file(ca_cert)
        ca_key_str = osw.read_str_from_file(ca_key)

        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

        valid, mess = osw.verify(ca_cert_str, cert_str)
        self.assertTrue(valid)

        false_ca_cert, false_ca_key = osw.create_certificate(cert_info_ca, request=False, write_to_file=False)
        false_req_cert_str_1, false_req_key_str_1 = osw.create_certificate(cert_info_ca, request=True)
        false_cert_str_1 = osw.create_cert_signed_certificate(false_ca_cert, false_ca_key, false_req_cert_str_1)
        false_req_cert_str_2, false_req_key_str_2 = osw.create_certificate(cert_info, request=True)
        false_cert_str_2 = osw.create_cert_signed_certificate(false_ca_cert, false_ca_key, false_req_cert_str_2)

        valid, mess = osw.verify(false_ca_cert, cert_str)
        self.assertFalse(valid)
        valid, mess = osw.verify(false_ca_cert, false_cert_str_1)
        self.assertFalse(valid)
        valid, mess = osw.verify(ca_cert_str, false_cert_str_2)
        self.assertFalse(valid)

        if "z" in cert_str:
            false_cert_str = cert_str.replace("z", "x")
            valid, mess = osw.verify(ca_cert_str, false_cert_str)
            self.assertFalse(valid)

        remove(ca_cert)
        remove(ca_key)

    def test_validate_cert_chains(self):

        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }

        cert_intermediate_1_info = {
            "cn": "intermediate_1",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        cert_intermediate_2_info = {
            "cn": "intermediate_2",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        cert_client_cert_info = {
            "cn": "intermediate_1",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        osw = OpenSSLWrapper()

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False)

        req_cert_str, intermediate_1_key_str = osw.create_certificate(cert_intermediate_1_info, request=True)
        intermediate_cert_1_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

        req_cert_str, intermediate_2_key_str = osw.create_certificate(cert_intermediate_2_info, request=True)
        intermediate_cert_2_str = osw.create_cert_signed_certificate(
            intermediate_cert_1_str, intermediate_1_key_str, req_cert_str
        )

        req_cert_str, client_key_str = osw.create_certificate(cert_client_cert_info, request=True)
        client_cert_str = osw.create_cert_signed_certificate(
            intermediate_cert_2_str, intermediate_2_key_str, req_cert_str
        )

        cert_chain = [intermediate_cert_2_str, intermediate_cert_1_str, ca_cert_str]

        valid, mess = osw.verify_chain(cert_chain, client_cert_str)
        self.assertTrue(valid)

    def test_validate_passphrase(self):

        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }

        cert_info = {
            "cn": "intermediate_1",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        osw = OpenSSLWrapper()

        ca_cert_str, ca_key_str = osw.create_certificate(
            cert_info_ca, request=False, cipher_passphrase={"cipher": "blowfish", "passphrase": "qwerty"}
        )

        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str, passphrase=b"qwerty")

        valid = False
        try:
            cert_str = osw.create_cert_signed_certificate(
                ca_cert_str, ca_key_str, req_cert_str, passphrase="qwertyqwerty"
            )
        except Exception:
            valid = True

        self.assertTrue(valid)

    def test_validate_expire(self):

        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }

        cert_info = {
            "cn": "intermediate_1",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        osw = OpenSSLWrapper()

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False)

        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

        valid, mess = osw.verify(ca_cert_str, cert_str)

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False, valid_from=1000, valid_to=100000)
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)
        valid, mess = osw.verify(ca_cert_str, cert_str)
        self.assertFalse(valid)

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False)
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(
            ca_cert_str, ca_key_str, req_cert_str, valid_from=1000, valid_to=100000
        )
        valid, mess = osw.verify(ca_cert_str, cert_str)
        self.assertFalse(valid)

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False, valid_from=0, valid_to=1)
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)
        time.sleep(2)
        valid, mess = osw.verify(ca_cert_str, cert_str)
        self.assertFalse(valid)

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False)
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str, valid_from=0, valid_to=1)
        time.sleep(2)
        valid, mess = osw.verify(ca_cert_str, cert_str)
        self.assertFalse(valid)

    def _build_chain(self, osw, root_valid_to=315360000):
        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }

        cert_intermediate_1_info = {
            "cn": "intermediate_1",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        cert_intermediate_2_info = {
            "cn": "intermediate_2",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        cert_client_cert_info = {
            "cn": "client",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        ca_cert_str, ca_key_str = osw.create_certificate(
            cert_info_ca, request=False, valid_from=0, valid_to=root_valid_to
        )

        req_cert_str, intermediate_1_key_str = osw.create_certificate(cert_intermediate_1_info, request=True)
        intermediate_cert_1_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

        req_cert_str, intermediate_2_key_str = osw.create_certificate(cert_intermediate_2_info, request=True)
        intermediate_cert_2_str = osw.create_cert_signed_certificate(
            intermediate_cert_1_str, intermediate_1_key_str, req_cert_str
        )

        req_cert_str, client_key_str = osw.create_certificate(cert_client_cert_info, request=True)
        client_cert_str = osw.create_cert_signed_certificate(
            intermediate_cert_2_str, intermediate_2_key_str, req_cert_str
        )

        cert_chain = [intermediate_cert_2_str, intermediate_cert_1_str, ca_cert_str]
        return cert_chain, client_cert_str, ca_cert_str, ca_key_str

    def test_validate_cert_chain_wrong_root(self):
        """A chain with valid links but an untrusted root must be rejected."""
        osw = OpenSSLWrapper()

        cert_chain, client_cert_str, ca_cert_str, ca_key_str = self._build_chain(osw)

        # A different, unrelated root certificate placed at the end of the
        # chain must not make the chain trusted.
        rogue_info = {
            "cn": "rogue",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }
        rogue_cert, rogue_key = osw.create_certificate(rogue_info, request=False)

        bad_chain = [cert_chain[0], cert_chain[1], rogue_cert]
        valid, mess = osw.verify_chain(bad_chain, client_cert_str)
        self.assertFalse(valid)

    def test_validate_cert_chain_expired_root(self):
        """A chain ending in an expired root must be rejected."""
        osw = OpenSSLWrapper()

        cert_chain, client_cert_str, ca_cert_str, ca_key_str = self._build_chain(osw, root_valid_to=1)
        time.sleep(2)

        valid, mess = osw.verify_chain(cert_chain, client_cert_str)
        self.assertFalse(valid)

    def test_validate_cert_chain_broken_link(self):
        """A chain where an intermediate is not signed by the next one fails."""
        osw = OpenSSLWrapper()

        cert_chain, client_cert_str, ca_cert_str, ca_key_str = self._build_chain(osw)

        rogue_info = {
            "cn": "rogue",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }
        rogue_cert, rogue_key = osw.create_certificate(rogue_info, request=False)
        intermediate_info = {
            "cn": "intermediate_1",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }
        req_cert_str, rogue_intermediate_key = osw.create_certificate(intermediate_info, request=True)
        rogue_intermediate = osw.create_cert_signed_certificate(rogue_cert, rogue_key, req_cert_str)

        bad_chain = [cert_chain[0], rogue_intermediate, ca_cert_str]
        valid, mess = osw.verify_chain(bad_chain, client_cert_str)
        self.assertFalse(valid)

    def test_validate_cert_chain_single_root(self):
        """A leaf signed directly by a single trusted root stays valid."""
        osw = OpenSSLWrapper()

        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }
        cert_info = {
            "cn": "asdfgh",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False)
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

        valid, mess = osw.verify_chain([ca_cert_str], cert_str)
        self.assertTrue(valid)

    def test_verify_root(self):
        osw = OpenSSLWrapper()

        cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }
        cert_info = {
            "cn": "asdfgh",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }

        ca_cert_str, ca_key_str = osw.create_certificate(cert_info_ca, request=False)
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True)
        leaf_cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

        valid, mess = osw.verify_root(ca_cert_str)
        self.assertTrue(valid)

        # A non-self-signed certificate is not a valid root.
        valid, mess = osw.verify_root(leaf_cert_str)
        self.assertFalse(valid)

        # An expired self-signed root is not a valid root.
        expired_cert, expired_key = osw.create_certificate(
            cert_info_ca, request=False, valid_from=0, valid_to=1
        )
        time.sleep(2)
        valid, mess = osw.verify_root(expired_cert)
        self.assertFalse(valid)


class TestCertHandler(unittest.TestCase):
    def setUp(self):
        self.osw = OpenSSLWrapper()
        self.cert_info_ca = {
            "cn": "qwerty",
            "country_code": "qw",
            "state": "qwerty",
            "city": "qwerty",
            "organization": "qwerty",
            "organization_unit": "qwerty",
        }
        self.cert_info = {
            "cn": "asdfgh",
            "country_code": "as",
            "state": "asdfgh",
            "city": "asdfgh",
            "organization": "asdfgh",
            "organization_unit": "asdfg",
        }
        self.tmpdir = tempfile.mkdtemp()

    def _write(self, name, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as fp:
            fp.write(data)
        return path

    def _make_leaf(self, ca_cert_str, ca_key_str):
        req_cert_str, req_key_str = self.osw.create_certificate(self.cert_info, request=True)
        return self.osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)

    def _handler(self, ca_cert_file, ca_key_file, **kwargs):
        class _DummySecurityContext:
            pass

        return CertHandler(_DummySecurityContext(), cert_file=ca_cert_file, key_file=ca_key_file, **kwargs)

    def test_failed_validation_keeps_last_trusted_cert(self):
        ca_cert_str, ca_key_str = self.osw.create_certificate(self.cert_info_ca, request=False)
        ca_cert_file = self._write("ca.crt", ca_cert_str)
        ca_key_file = self._write("ca.key", ca_key_str)

        trusted_leaf = self._make_leaf(ca_cert_str, ca_key_str)
        trusted_leaf_file = self._write("trusted.crt", trusted_leaf)

        rogue_cert, rogue_key = self.osw.create_certificate(self.cert_info_ca, request=False)
        rogue_leaf = self._make_leaf(rogue_cert, rogue_key)
        rogue_leaf_file = self._write("rogue.crt", rogue_leaf)

        handler = self._handler(ca_cert_file, ca_key_file, verify_cert=True)
        self.assertIsNone(handler._last_validated_cert)

        self.assertTrue(handler.verify_cert(trusted_leaf_file))
        self.assertEqual(handler._last_validated_cert, trusted_leaf.encode("ascii"))

        # A failing validation must not overwrite the last trusted certificate.
        self.assertFalse(handler.verify_cert(rogue_leaf_file))
        self.assertEqual(handler._last_validated_cert, trusted_leaf.encode("ascii"))

        # Missing files must not break the entry point nor clear the evidence.
        self.assertFalse(handler.verify_cert(None))
        self.assertFalse(handler.verify_cert(os.path.join(self.tmpdir, "missing.crt")))
        self.assertEqual(handler._last_validated_cert, trusted_leaf.encode("ascii"))

    def test_verification_disabled_is_legacy_compatible(self):
        ca_cert_str, ca_key_str = self.osw.create_certificate(self.cert_info_ca, request=False)
        ca_cert_file = self._write("ca.crt", ca_cert_str)
        ca_key_file = self._write("ca.key", ca_key_str)

        rogue_cert, rogue_key = self.osw.create_certificate(self.cert_info_ca, request=False)
        rogue_leaf = self._make_leaf(rogue_cert, rogue_key)
        rogue_leaf_file = self._write("rogue.crt", rogue_leaf)

        # Old callers that do not enable verification keep getting True and
        # no validation state is recorded.
        handler = self._handler(ca_cert_file, ca_key_file, verify_cert=False)
        self.assertTrue(handler.verify_cert(rogue_leaf_file))
        self.assertIsNone(handler._last_validated_cert)
        self.assertTrue(handler.verify_cert(None))

    def test_extension_class_without_generation_config(self):
        ca_cert_str, ca_key_str = self.osw.create_certificate(self.cert_info_ca, request=False)
        ca_cert_file = self._write("ca.crt", ca_cert_str)
        ca_key_file = self._write("ca.key", ca_key_str)
        leaf_file = self._write("leaf.crt", self._make_leaf(ca_cert_str, ca_key_str))

        class FailingExtra:
            def use_validate_cert_func(self):
                return True

            def validate_cert(self, cert_str, root_cert_string, root_key_string):
                return False

        class PassingExtra:
            def use_validate_cert_func(self):
                return True

            def validate_cert(self, cert_str, root_cert_string, root_key_string):
                # Legacy implementations only raise on failure and return None.
                return None

        failing = self._handler(
            ca_cert_file, ca_key_file, verify_cert=True, cert_handler_extra_class=FailingExtra()
        )
        self.assertFalse(failing.verify_cert(leaf_file))
        self.assertIsNone(failing._last_validated_cert)

        passing = self._handler(
            ca_cert_file, ca_key_file, verify_cert=True, cert_handler_extra_class=PassingExtra()
        )
        self.assertTrue(passing.verify_cert(leaf_file))
        self.assertIsNotNone(passing._last_validated_cert)
