"""One latest Pillar value can serve both compilation caching and targeting."""

import datetime
from types import SimpleNamespace

import pytest

import salt.cache
import salt.master
import salt.pillar
import salt.utils.minions
from tests.support.mock import AsyncMock, MagicMock, patch

MINION_ID = "minion-1"
PILLARS = {
    None: {"role": "all"},
    "dev": {"role": "web"},
    "prod": {"role": "db"},
}


@pytest.fixture
def opts(master_opts):
    master_opts.update(
        {
            "pillar_cache": True,
            "minion_data_cache": True,
            "minion_data_cache_events": False,
            "memcache_expire_seconds": 0,
            "cache": "localfs",
            "pillar.cache_driver": None,
        }
    )
    return master_opts


def _handler(opts):
    handler = salt.master.AESFuncs.__new__(salt.master.AESFuncs)
    handler.opts = opts
    handler.masterapi = SimpleNamespace(cache=salt.cache.factory(opts))
    handler.fs_ = MagicMock()
    return handler


def _request(handler, env, **kwargs):
    return handler._sync_pillar(
        {"id": MINION_ID, "grains": {}, "pillarenv": env, **kwargs}
    )


def _matched(opts, role):
    matcher = salt.utils.minions.CkMinions.__new__(salt.utils.minions.CkMinions)
    matcher.opts = opts
    matcher.cache = salt.cache.factory(opts)
    matcher._pki_minions = lambda: [MINION_ID]
    for method in (matcher._check_pillar_minions, matcher._check_pillar_pcre_minions):
        assert set(method(f"role:{role}", ":", True)["minions"]) == {MINION_ID}


def test_only_latest_environment_is_reused(opts):
    handler = _handler(opts)
    with patch(
        "salt.pillar.Pillar.compile_pillar",
        autospec=True,
        side_effect=lambda pillar: PILLARS[pillar.opts["pillarenv"]],
    ) as compile_:
        assert _request(handler, "dev") == PILLARS["dev"]
        assert _request(handler, "dev") == PILLARS["dev"]
        assert compile_.call_count == 1
        _matched(opts, "web")
        assert _request(handler, "prod") == PILLARS["prod"]
        _matched(opts, "db")
        assert _request(handler, "dev") == PILLARS["dev"]
        assert compile_.call_count == 3

    cache = salt.cache.pillar_factory(opts)
    assert cache.list("pillar") == [MINION_ID]
    assert cache.fetch("pillar", MINION_ID) == PILLARS["dev"]
    assert cache.fetch("pillar_cache_status", MINION_ID)["pillarenv"] == "dev"


def test_mismatched_status_does_not_return_another_environment(opts):
    handler = _handler(opts)
    with patch(
        "salt.pillar.Pillar.compile_pillar",
        autospec=True,
        side_effect=lambda pillar: PILLARS[pillar.opts["pillarenv"]],
    ) as compile_:
        _request(handler, "dev")
        # Simulate two workers interleaving their writes to the data and status.
        salt.cache.pillar_factory(opts).store("pillar", MINION_ID, PILLARS["prod"])
        assert _request(handler, "dev") == PILLARS["dev"]
        assert compile_.call_count == 2


def test_unspecified_environment_is_distinct(opts):
    handler = _handler(opts)
    with patch(
        "salt.pillar.Pillar.compile_pillar",
        autospec=True,
        side_effect=lambda pillar: PILLARS[pillar.opts["pillarenv"]],
    ) as compile_:
        assert _request(handler, None) == PILLARS[None]
        assert _request(handler, "dev") == PILLARS["dev"]
        assert _request(handler, None) == PILLARS[None]
        assert compile_.call_count == 3
    _matched(opts, "all")


def test_request_override_is_not_reused(opts):
    handler = _handler(opts)
    with patch(
        "salt.pillar.Pillar.compile_pillar", return_value=PILLARS["dev"]
    ) as compile_:
        assert _request(handler, "dev", pillar_override={"temporary": True}) == {
            **PILLARS["dev"],
            "temporary": True,
        }
        assert (
            salt.cache.pillar_factory(opts).fetch("pillar_cache_status", MINION_ID)
            == {}
        )
        assert _request(handler, "dev") == PILLARS["dev"]
        assert compile_.call_count == 2


def test_expired_compilation_keeps_targeting_snapshot(opts):
    real_datetime = datetime.datetime
    elapsed = datetime.timedelta()

    class Clock(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + elapsed

    opts["pillar_cache_ttl"] = 60
    handler = _handler(opts)
    with patch("salt.cache.datetime.datetime", Clock), patch(
        "salt.pillar.Pillar.compile_pillar", return_value=PILLARS["dev"]
    ) as compile_:
        _request(handler, "dev")
        elapsed = datetime.timedelta(seconds=61)
        assert (
            salt.cache.pillar_factory(opts).fetch("pillar_cache_status", MINION_ID)
            == {}
        )
        _matched(opts, "web")
        _request(handler, "dev")
        assert compile_.call_count == 2


def test_custom_pillar_driver_is_used_for_targeting(opts, tmp_path):
    opts["pillar.cache_driver"] = "separate"
    grains_cache = salt.cache.factory({**opts, "cachedir": str(tmp_path / "grains")})
    pillar_cache = salt.cache.factory({**opts, "cachedir": str(tmp_path / "pillar")})

    def factory(config, **kwargs):
        return pillar_cache if kwargs.get("driver") == "separate" else grains_cache

    with patch("salt.cache.factory", side_effect=factory), patch(
        "salt.pillar.Pillar.compile_pillar", return_value=PILLARS["dev"]
    ):
        handler = _handler(opts)
        _request(handler, "dev")
        _matched(opts, "web")
        assert salt.utils.minions.get_minion_data(MINION_ID, opts)[2] == PILLARS["dev"]
    assert grains_cache.fetch("pillar", MINION_ID) == {}
    assert pillar_cache.fetch("pillar", MINION_ID) == PILLARS["dev"]


def test_no_compilation_cache_still_updates_targeting(opts):
    opts["pillar_cache"] = False
    handler = _handler(opts)
    with patch(
        "salt.pillar.Pillar.compile_pillar", return_value=PILLARS["dev"]
    ) as compile_:
        _request(handler, "dev")
        _request(handler, "dev")
        assert compile_.call_count == 2
    _matched(opts, "web")


async def test_async_request_replaces_snapshot_and_invalidates_status(opts):
    handler = _handler(opts)
    with patch("salt.pillar.Pillar.compile_pillar", return_value=PILLARS["dev"]):
        _request(handler, "dev")

    handler.event = SimpleNamespace(fire_event_async=AsyncMock())
    pillar = SimpleNamespace(compile_pillar=AsyncMock(return_value=PILLARS["prod"]))
    with patch("salt.pillar.get_async_pillar", return_value=pillar):
        assert (
            await handler._pillar({"id": MINION_ID, "grains": {}, "pillarenv": "prod"})
            == PILLARS["prod"]
        )

    cache = salt.cache.pillar_factory(opts)
    assert cache.fetch("pillar", MINION_ID) == PILLARS["prod"]
    assert cache.fetch("pillar_cache_status", MINION_ID) == {}
    _matched(opts, "db")
