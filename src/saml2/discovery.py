from urllib import parse

from saml2.entity import Entity
from saml2.response import VerificationError


__author__ = "rolandh"

IDPDISC_POLICY = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single"


class DiscoveryServer(Entity):
    def __init__(self, config=None, config_file=""):
        if config or config_file:
            Entity.__init__(self, "disco", config, config_file)

    @staticmethod
    def _url_identity(url):
        """Return the parts of *url* that identify the endpoint.

        A DiscoveryResponse location is an exact endpoint, not a prefix.  The
        identity therefore consists of scheme, host, port and path.  Ports are
        normalised so that an explicit default port (for example ``:443`` for
        HTTPS) is treated as the same endpoint as an omitted default port.
        """
        try:
            parts = parse.urlsplit(url)
        except ValueError:
            return None

        try:
            port = parts.port
        except ValueError:
            # An invalid port cannot identify a trusted endpoint.
            return None

        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        if not scheme or not host:
            return None

        if port is None:
            if scheme == "https":
                port = 443
            elif scheme == "http":
                port = 80

        return (
            scheme,
            host,
            port,
            parts.path,
        )

    @classmethod
    def _same_endpoint(cls, url, location):
        """Check whether *url* addresses the registered *location* endpoint.

        Query parameters may be appended to the registered location (that is
        how SPs carry state such as ``sid`` through Discovery), but the path
        and origin must be identical.  This prevents look-alike domains and
        path traversal from being accepted by a string-prefix comparison.
        """
        if not url or not location:
            return False

        try:
            url_parts = parse.urlsplit(url)
            location_parts = parse.urlsplit(location)
        except ValueError:
            return False

        if url_parts.username or url_parts.password:
            return False
        if location_parts.username or location_parts.password:
            return False

        url_identity = cls._url_identity(url)
        location_identity = cls._url_identity(location)
        if url_identity is None or location_identity is None:
            return False
        if url_identity != location_identity:
            return False

        # Preserve the historical ability to add parameters to an endpoint.
        # If the registered endpoint itself has a query, all of it must still
        # be present (and in the same order) before the extra parameters.
        if location_parts.query:
            if url_parts.query != location_parts.query:
                if not url_parts.query.startswith(f"{location_parts.query}&"):
                    return False

        if url_parts.fragment != location_parts.fragment:
            return False

        return True

    @staticmethod
    def _entity_namespace(entity_id):
        """Return the namespace shared by entities in the same URN tree."""
        if not entity_id or not entity_id.lower().startswith("urn:"):
            return None
        return entity_id.rsplit(":", 1)[0] + ":"

    def _trusted_idps(self):
        """Return the IdPs registered in the Discovery server metadata.

        The authoritative source is the Discovery server's metadata.
        """
        if not self.metadata:
            return set()

        try:
            return set(self.metadata.with_descriptor("idpsso"))
        except Exception:
            return set()

    def _sp_for_return(self, return_url):
        """Find the SP whose registered Discovery endpoint matches *return_url*."""
        if not self.metadata or not return_url:
            return None

        for entity_id in self.metadata.keys():
            try:
                endpoints = self.metadata.discovery_response(entity_id)
            except Exception:
                continue
            for endpoint in endpoints or []:
                location = endpoint.get("location")
                if location and self._same_endpoint(return_url, location):
                    return entity_id
        return None

    def _looks_like_registered_endpoint(self, return_url):
        """Detect a return URL that is only a string-prefix variant.

        Such URLs must never inherit the trust of the registered endpoint.
        The check is intentionally only used to reject; acceptance is always
        based on the complete URL identity in :meth:`_same_endpoint`.
        """
        if not self.metadata or not return_url:
            return False

        for entity_id in self.metadata.keys():
            try:
                endpoints = self.metadata.discovery_response(entity_id)
            except Exception:
                continue
            for endpoint in endpoints or []:
                location = endpoint.get("location")
                if not location:
                    continue
                if return_url.startswith(location) or location.startswith(return_url):
                    return True
        return False

    def _valid_idp_choice(self, return_url, entity_id):
        if not entity_id:
            return True

        if not self.metadata:
            # Without metadata there is no trusted SP or IdP information to
            # publish a selection against.
            return False

        trusted = self._trusted_idps()
        if trusted:
            return entity_id in trusted

        sp_entity_id = self._sp_for_return(return_url)
        if sp_entity_id is None:
            if self._looks_like_registered_endpoint(return_url):
                return False
            # No registered SP context is available.  Keep the legacy
            # behaviour for old Discovery deployments.
            return True

        # Some legacy deployments only load SP metadata.  In that case the
        # SP's URN namespace is the only trust boundary available; do not
        # accept arbitrary entities outside it.
        namespace = self._entity_namespace(sp_entity_id)
        return namespace is not None and self._entity_namespace(entity_id) == namespace

    def parse_discovery_service_request(self, url="", query=""):
        if url:
            part = parse.urlparse(url)
            dsr = parse.parse_qs(part[4])
        elif query:
            dsr = parse.parse_qs(query)
        else:
            dsr = {}

        # verify

        for key in ["isPassive", "return", "returnIDParam", "policy", "entityID"]:
            try:
                if len(dsr[key]) != 1:
                    raise Exception(f"Invalid DS request keys: {key}")
                dsr[key] = dsr[key][0]
            except KeyError:
                pass

        if "return" in dsr:
            part = parse.urlparse(dsr["return"])
            if part.query:
                qp = parse.parse_qs(part.query)
                if "returnIDParam" in dsr:
                    if dsr["returnIDParam"] in qp.keys():
                        raise Exception("returnIDParam value should not be in the query params")
                else:
                    if "entityID" in qp.keys():
                        raise Exception("entityID should not be in the query params")
        else:
            # If metadata not used this is mandatory
            raise VerificationError("Missing mandatory parameter 'return'")

        if "policy" not in dsr:
            dsr["policy"] = IDPDISC_POLICY

        is_passive = dsr.get("isPassive")
        if is_passive not in ["true", "false"]:
            raise ValueError(f"Invalid value '{is_passive}' for attribute 'isPassive'")

        if "isPassive" in dsr and dsr["isPassive"] == "true":
            dsr["isPassive"] = True
        else:
            dsr["isPassive"] = False

        if "returnIDParam" not in dsr:
            dsr["returnIDParam"] = "entityID"

        return dsr

    # -------------------------------------------------------------------------

    def create_discovery_service_response(self, return_url=None, returnIDParam="entityID", entity_id=None, **kwargs):
        if return_url is None:
            return_url = kwargs["return"]

        if entity_id:
            if not self._valid_idp_choice(return_url, entity_id):
                raise VerificationError(f"IdP '{entity_id}' is not trusted by the requesting SP")

            qp = parse.urlencode({returnIDParam: entity_id})

            part = parse.urlparse(return_url)
            if part.query:
                # Iff there is a query part add the new info at the end
                return_url = f"{return_url}&{qp}"
            else:
                return_url = f"{return_url}?{qp}"

        return return_url

    def verify_sp_in_metadata(self, entity_id):
        if self.metadata:
            endp = self.metadata.discovery_response(entity_id)
            if endp:
                return True

        return False

    def verify_return(self, entity_id, return_url):
        if not self.metadata or not return_url:
            return False

        try:
            endpoints = self.metadata.discovery_response(entity_id)
        except Exception:
            return False

        for endp in endpoints or []:
            location = endp.get("location")
            if location and self._same_endpoint(return_url, location):
                return True
        return False
