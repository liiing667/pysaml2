#!/usr/bin/env python
"""Authentication response transaction binding and replay protection.

These tests make sure that:

* a response only establishes a login when it answers an authentication
  request that belongs to the same transaction (matching ``InResponseTo`` and,
  when recorded, the expected IdP issuer);
* a response (or assertion) that has already been consumed is rejected on
  redelivery;
* a response rejected for any reason leaves the outstanding request in place
  so a legitimate retry still works;
* IdP initiated (unsolicited) POST and synchronous SOAP/PAOS style responses
  remain usable.
"""

from base64 import b64encode
from contextlib import closing

import pytest

from pathutils import dotname

from saml2 import BINDING_HTTP_POST
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.config import config_factory
from saml2.response import AuthnResponse
from saml2.response import UnsolicitedResponse
from saml2.response import authn_response
from saml2.response import response_factory
from saml2.response import reset_consumed_assertion_ids
from saml2.response import reset_consumed_response_ids
from saml2.server import Server


SP_ENTITY_ID = "urn:mace:example.com:saml:roland:sp"
IDP_ENTITY_ID = "urn:mace:example.com:saml:roland:idp"
CONSUMER_URL = "http://lingon.catalogix.se:8087/"
AUTHN = {"class_ref": INTERNETPROTOCOLPASSWORD, "authn_auth": "http://www.example.com/login"}
IDENTITY = {"mail": ["derek@example.com"]}


def _make_response(server, in_response_to, sp_entity_id=SP_ENTITY_ID):
    name_id = server.ident.transient_nameid(sp_entity_id, in_response_to)
    return str(
        server.create_authn_response(
            IDENTITY,
            in_response_to,
            CONSUMER_URL,
            sp_entity_id,
            name_id=name_id,
            authn=AUTHN,
        )
    )


def _make_authn_response():
    conf = config_factory("sp", dotname("server_conf"))
    conf.only_use_keys_in_metadata = False
    response = authn_response(conf, CONSUMER_URL)
    response.timeslack = 100000
    # Isolated registries so the tests do not influence each other and do not
    # depend on the process wide replay registries.
    response.consumed_response_ids = set()
    response.consumed_assertion_ids = set()
    return response


@pytest.fixture(scope="module")
def server():
    with closing(Server(dotname("idp_conf"))) as idp:
        yield idp


@pytest.fixture(autouse=True)
def _reset_global_replay_registries():
    reset_consumed_response_ids()
    reset_consumed_assertion_ids()
    yield
    reset_consumed_response_ids()
    reset_consumed_assertion_ids()


def test_legacy_string_outstanding_query_logs_in_and_is_consumed(server):
    """The original ``{id: came_from}`` mapping keeps working."""
    xml_response = _make_response(server, "id12")
    outstanding = {"id12": "http://localhost:8088/sso"}

    response = _make_authn_response()
    response.outstanding_queries = outstanding
    response.loads(xml_response, decode=False)
    # loads() binds the transaction but must not consume it yet.
    assert "id12" in outstanding
    assert response.came_from == "http://localhost:8088/sso"
    response.verify()

    assert response.issuer() == IDP_ENTITY_ID
    # The transaction is consumed once the login is established.
    assert "id12" not in outstanding


def test_redelivery_of_consumed_response_is_rejected(server):
    """The same response delivered twice must never create two logins."""
    xml_response = _make_response(server, "id12")
    consumed_responses = set()
    consumed_assertions = set()

    first = _make_authn_response()
    first.consumed_response_ids = consumed_responses
    first.consumed_assertion_ids = consumed_assertions
    first.outstanding_queries = {"id12": "/original-page"}
    first.loads(xml_response, decode=False)
    first.verify()

    second = _make_authn_response()
    second.consumed_response_ids = consumed_responses
    second.consumed_assertion_ids = consumed_assertions
    # Even if the attacker (or a buggy application) re-creates the
    # outstanding entry, the consumed response id still blocks the replay.
    second.outstanding_queries = {"id12": "/original-page"}

    with pytest.raises(UnsolicitedResponse):
        second.loads(xml_response, decode=False)


def test_rewrapped_assertion_replay_is_rejected(server):
    """A consumed assertion re-wrapped in a new Response id is blocked."""
    xml_response = _make_response(server, "id12")
    consumed_responses = set()
    consumed_assertions = set()

    first = _make_authn_response()
    first.consumed_response_ids = consumed_responses
    first.consumed_assertion_ids = consumed_assertions
    first.outstanding_queries = {"id12": "/original-page"}
    first.loads(xml_response, decode=False)
    first.verify()

    # The attacker keeps the assertion but mints a fresh Response envelope.
    rewrapped = xml_response.replace(f'ID="{first.response.id}"', 'ID="brand-new-response-id"', 1)
    assert "brand-new-response-id" in rewrapped

    second = _make_authn_response()
    second.consumed_response_ids = consumed_responses
    second.consumed_assertion_ids = consumed_assertions
    second.outstanding_queries = {"id12": "/original-page"}
    with pytest.raises(UnsolicitedResponse):
        second.loads(rewrapped, decode=False)


def test_unknown_in_response_to_is_rejected_and_request_is_preserved(server):
    """An InResponseTo that matches no issued request is unsolicited."""
    xml_response = _make_response(server, "id12")

    response = _make_authn_response()
    response.outstanding_queries = {"some-other-request": "/page"}

    with pytest.raises(UnsolicitedResponse):
        response.loads(xml_response, decode=False)

    # Nothing was consumed, so a legitimate response can still arrive.
    assert response.outstanding_queries == {"some-other-request": "/page"}


def test_issuer_mismatch_rejects_spliced_response(server):
    """An InResponseTo of one transaction paired with another IdP's issuer."""
    xml_response = _make_response(server, "id12")

    response = _make_authn_response()
    response.outstanding_queries = {"id12": {"came_from": "/page", "issuer": "urn:foreign:evil:idp"}}

    with pytest.raises(UnsolicitedResponse):
        response.loads(xml_response, decode=False)

    # The mismatched response must not consume the genuine transaction.
    assert "id12" in response.outstanding_queries


def test_expected_issuer_match_allows_login(server):
    xml_response = _make_response(server, "id12")
    outstanding = {"id12": {"came_from": "/page", "issuer": IDP_ENTITY_ID}}

    response = _make_authn_response()
    response.outstanding_queries = outstanding
    response.loads(xml_response, decode=False)
    assert "id12" in outstanding
    response.verify()

    assert response.came_from == "/page"
    assert not outstanding


def test_failed_verification_keeps_request_for_retry(server):
    """A response that parses but fails verification must not be consumed."""
    xml_response = _make_response(server, "id12")
    outstanding = {"id12": "/page"}

    response = _make_authn_response()
    response.outstanding_queries = outstanding
    response.loads(xml_response, decode=False)
    # Break the response after binding so verify() fails; the transaction and
    # replay registries must remain untouched.
    response.response.destination = "http://unexpected.example/acs"
    assert response.verify() is None

    assert "id12" in outstanding
    assert response.consumed_response_ids == set()
    assert response.consumed_assertion_ids == set()

    # A fresh, legitimate response for the same request now succeeds.
    retry = _make_authn_response()
    retry.consumed_response_ids = response.consumed_response_ids
    retry.consumed_assertion_ids = response.consumed_assertion_ids
    retry.outstanding_queries = outstanding
    retry.loads(xml_response, decode=False)
    retry.verify()
    assert retry.came_from == "/page"
    assert not outstanding


def test_failed_response_keeps_request_for_retry(server):
    """A malformed response cannot consume the authentication transaction."""
    response = _make_authn_response()
    response.outstanding_queries = {"id12": "/page"}

    with pytest.raises(Exception):
        response.loads("<this-is-not-valid-xml", decode=False)

    assert "id12" in response.outstanding_queries

    # The legitimate response for the still outstanding request succeeds.
    xml_response = _make_response(server, "id12")
    retry = _make_authn_response()
    retry.outstanding_queries = response.outstanding_queries
    retry.loads(xml_response, decode=False)
    retry.verify()
    assert retry.came_from == "/page"


def test_unsolicited_post_allowed_but_replay_rejected(server):
    """IdP initiated SSO still works, yet cannot be replayed."""
    xml_response = _make_response(server, "id12")
    consumed_responses = set()
    consumed_assertions = set()

    first = _make_authn_response()
    first.allow_unsolicited = True
    first.consumed_response_ids = consumed_responses
    first.consumed_assertion_ids = consumed_assertions
    first.outstanding_queries = {}
    first.loads(xml_response, decode=False)
    first.verify()

    second = _make_authn_response()
    second.allow_unsolicited = True
    second.consumed_response_ids = consumed_responses
    second.consumed_assertion_ids = consumed_assertions
    second.outstanding_queries = {}
    with pytest.raises(UnsolicitedResponse):
        second.loads(xml_response, decode=False)


def test_synchronous_soap_response_does_not_require_outstanding_query(server):
    """SOAP/PAOS back-channel responses are synchronous and keep working."""
    xml_response = _make_response(server, "id12")
    conf = config_factory("sp", dotname("server_conf"))
    response = authn_response(conf, CONSUMER_URL, asynchop=False, allow_unsolicited=True)
    response.timeslack = 100000
    response.loads(xml_response, decode=False)
    assert response.verify() is not None


def test_two_independent_transactions_each_login_once(server):
    xml_one = _make_response(server, "req-one")
    xml_two = _make_response(server, "req-two")
    outstanding = {
        "req-one": {"came_from": "/a", "issuer": IDP_ENTITY_ID},
        "req-two": {"came_from": "/b", "issuer": IDP_ENTITY_ID},
    }

    first = _make_authn_response()
    first.outstanding_queries = outstanding
    first.loads(xml_one, decode=False)
    assert "req-one" in outstanding
    first.verify()
    assert first.came_from == "/a"
    assert "req-one" not in outstanding and "req-two" in outstanding

    second = _make_authn_response()
    second.consumed_response_ids = first.consumed_response_ids
    second.consumed_assertion_ids = first.consumed_assertion_ids
    second.outstanding_queries = outstanding
    second.loads(xml_two, decode=False)
    second.verify()
    assert second.came_from == "/b"
    assert not outstanding


def test_authresponse_accepts_injected_replay_registries(server):
    assert isinstance(_make_authn_response(), AuthnResponse)


def test_response_factory_enforces_transaction_binding_and_replay(server):
    """The legacy response_factory entry point must apply the same checks."""
    xml_response = _make_response(server, "id12")
    conf = config_factory("sp", dotname("server_conf"))

    def build(outstanding):
        return response_factory(
            xml_response,
            conf,
            return_addrs=[CONSUMER_URL],
            outstanding_queries=outstanding,
            timeslack=100000,
            decode=False,
        )

    outstanding = {"id12": "/factory-page"}
    first = build(outstanding)
    first.verify()
    assert first.came_from == "/factory-page"
    assert not outstanding

    # The redelivery can no longer match a live transaction.
    with pytest.raises(UnsolicitedResponse):
        build({"id12": "/factory-page"})

    reset_consumed_response_ids()
    reset_consumed_assertion_ids()

    # An issuer recorded on the transaction is enforced on this path too.
    with pytest.raises(UnsolicitedResponse):
        build({"id12": {"came_from": "/x", "issuer": "urn:foreign:evil:idp"}})

    # A matching issuer still succeeds.
    reset_consumed_response_ids()
    reset_consumed_assertion_ids()
    matched = build({"id12": {"came_from": "/x", "issuer": IDP_ENTITY_ID}})
    matched.verify()
    assert matched.came_from == "/x"


def test_client_end_to_end_replay_and_issuer_binding():
    """The full Saml2Client flow rejects replays and spliced issuers."""
    reset_consumed_response_ids()
    reset_consumed_assertion_ids()

    client = Saml2Client(config_file=dotname("servera_conf"))
    client.want_response_signed = False
    client.want_assertions_signed = False
    client.want_assertions_or_response_signed = False

    with closing(Server(dotname("idp_all_conf"))) as idp:
        _, destination = idp.pick_binding(
            "assertion_consumer_service", entity_id=client.config.entityid
        )

        name_id = idp.ident.transient_nameid("id-1", client.config.entityid)
        response = idp.create_authn_response(
            IDENTITY,
            "id-1",
            destination,
            client.config.entityid,
            name_id=name_id,
            authn=AUTHN,
        )
        encoded = b64encode(str(response).encode())
        idp_issuer = idp.config.entityid

        outstanding = {"id-1": {"came_from": "/dashboard", "issuer": idp_issuer}}
        first = client.parse_authn_request_response(encoded, BINDING_HTTP_POST, outstanding)
        assert first is not None
        assert first.came_from == "/dashboard"
        assert not outstanding

        # Redelivery is blocked even if the outstanding entry is recreated.
        replayed = {"id-1": {"came_from": "/dashboard", "issuer": idp_issuer}}
        with pytest.raises(UnsolicitedResponse):
            client.parse_authn_request_response(encoded, BINDING_HTTP_POST, replayed)

        # A response whose issuer does not match the transaction is rejected,
        # and the genuine request survives for a legitimate retry.
        other_name_id = idp.ident.transient_nameid("id-2", client.config.entityid)
        other = idp.create_authn_response(
            IDENTITY,
            "id-2",
            destination,
            client.config.entityid,
            name_id=other_name_id,
            authn=AUTHN,
        )
        encoded_other = b64encode(str(other).encode())
        spliced = {"id-2": {"came_from": "/x", "issuer": "urn:evil:other-idp"}}
        with pytest.raises(UnsolicitedResponse):
            client.parse_authn_request_response(encoded_other, BINDING_HTTP_POST, spliced)
        assert "id-2" in spliced

        spliced["id-2"]["issuer"] = idp_issuer
        retry = client.parse_authn_request_response(encoded_other, BINDING_HTTP_POST, spliced)
        assert retry is not None and retry.came_from == "/x"
