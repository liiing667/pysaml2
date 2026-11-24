import logging

from saml2.cache import Cache
from saml2.cache import TooOld


logger = logging.getLogger(__name__)


def _session_indexes(value):
    """Return a set of session index values or None if no index was given."""
    if value is None:
        return None

    if isinstance(value, (list, tuple, set, frozenset)):
        values = value
    else:
        values = [value]

    indexes = {getattr(item, "text", item) for item in values}
    indexes.discard(None)
    return indexes or None


class Population:
    def __init__(self, cache=None):
        if cache:
            if isinstance(cache, str):
                self.cache = Cache(cache)
            else:
                self.cache = cache
        else:
            self.cache = Cache()

    def add_information_about_person(self, session_info):
        """If there already are information from this source in the cache
        this function will overwrite that information"""

        session_info = dict(session_info)
        name_id = session_info["name_id"]
        issuer = session_info.pop("issuer")
        self.cache.set(name_id, issuer, session_info, session_info["not_on_or_after"])
        return name_id

    def stale_sources_for_person(self, name_id, sources=None):
        """

        :param name_id: Identifier of the subject, a NameID instance
        :param sources: Sources for information about the subject
        :return:
        """
        if not sources:
            # assume that all the members has be asked
            # once before, hence they are represented in the cache
            sources = self.cache.entities(name_id)
        sources = [m for m in sources if not self.cache.active(name_id, m)]
        return sources

    def issuers_of_info(self, name_id):
        return self.cache.entities(name_id)

    def get_identity(self, name_id, entities=None, check_not_on_or_after=True):
        return self.cache.get_identity(name_id, entities, check_not_on_or_after)

    def get_info_from(self, name_id, entity_id, check_not_on_or_after=True):
        return self.cache.get(name_id, entity_id, check_not_on_or_after)

    def subjects(self):
        """Returns the name id's for all the persons in the cache"""
        return self.cache.subjects()

    def remove_person(self, name_id, entity_id=None, session_index=None):
        """Remove information about a subject.

        :param name_id: The identifier of the subject
        :param entity_id: If given only the information received from this
            entity is removed, otherwise all information about the subject is
            removed.
        :param session_index: If given, only remove the information if it
            still belongs to one of the given session indexes. This makes it
            possible to ignore responses for sessions that have already been
            replaced by a new login.
        :return: True if the requested information was removed
        """
        if entity_id is None:
            self.cache.delete(name_id)
            return True

        try:
            info = self.cache.get(name_id, entity_id, False)
        except (KeyError, TooOld):
            return False

        if not info:
            return False

        requested_indexes = _session_indexes(session_index)
        if requested_indexes is not None:
            current_indexes = _session_indexes(info.get("session_index"))
            if not current_indexes or not requested_indexes.intersection(current_indexes):
                return False

        try:
            self.cache.delete(name_id, entity_id)
        except TypeError:
            # Be compatible with cache implementations that only support
            # deleting all information about a subject.
            self.cache.reset(name_id, entity_id)
        return True

    def get_entityid(self, name_id, source_id, check_not_on_or_after=True):
        try:
            return self.cache.get(name_id, source_id, check_not_on_or_after)["name_id"]
        except (KeyError, ValueError):
            return ""

    def sources(self, name_id):
        return self.cache.entities(name_id)
