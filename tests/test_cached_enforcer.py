import os
from unittest import TestCase, IsolatedAsyncioTestCase

import casbin
from casbin.cache.default_cache import DefaultCache


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class TestCachedEnforcer(TestCase):
    def test_cache_basic(self):
        e = casbin.CachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        e.remove_policy("alice", "data1", "read")

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_cache_rbac(self):
        e = casbin.CachedEnforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        e.remove_policies([["alice", "data1", "read"], ["bob", "data2", "write"]])

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    def test_cache_clear_policy(self):
        e = casbin.CachedEnforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

        e.clear_policy()

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

    def test_cache_invalidate(self):
        e = casbin.CachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.invalidate_cache()

        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_cache_add_clears(self):
        e = casbin.CachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertFalse(e.enforce("alice", "data2", "read"))
        e.add_policy("alice", "data2", "read")
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_cache_enable_disable(self):
        e = casbin.CachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.enable_cache(False)
        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_cache_set_custom(self):
        e = casbin.CachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        e.set_cache(DefaultCache())
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_cache_get_key(self):
        key = casbin.CachedEnforcer.get_cache_key("alice", "data1", "read")
        self.assertEqual(key, "alice$$data1$$read$$")


class TestGFunctionCache(TestCase):
    def test_g_cache_basic(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_g_function_cache(True)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_g_cache_clear_on_add(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_g_function_cache(True)

        self.assertFalse(e.enforce("bob", "data2", "read"))
        e.add_grouping_policy("bob", "data2_admin")
        self.assertTrue(e.enforce("bob", "data2", "read"))

    def test_g_cache_clear_on_remove(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_g_function_cache(True)

        self.assertTrue(e.enforce("alice", "data2", "read"))
        e.remove_grouping_policy("alice", "data2_admin")
        self.assertFalse(e.enforce("alice", "data2", "read"))

    def test_g_cache_disable(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_g_function_cache(False)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_g_cache_with_domains(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        e.enable_g_function_cache(True)

        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))

    def test_g_cache_clear_on_load_policy(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_g_function_cache(True)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.load_policy()
        self.assertTrue(e.enforce("alice", "data1", "read"))


class TestSyncedCachedEnforcer(TestCase):
    def test_synced_cache_basic(self):
        e = casbin.SyncedCachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        e.remove_policy("alice", "data1", "read")

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_synced_cache_invalidate(self):
        e = casbin.SyncedCachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.invalidate_cache()
        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_synced_enable_cache(self):
        e = casbin.SyncedCachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.enable_cache(False)
        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_synced_g_function_cache(self):
        e = casbin.SyncedCachedEnforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_g_function_cache(True)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))

        e.add_grouping_policy("bob", "data2_admin")
        self.assertTrue(e.enforce("bob", "data2", "read"))


class TestAsyncCachedEnforcer(IsolatedAsyncioTestCase):
    async def test_async_cache_basic(self):
        e = casbin.AsyncCachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        await e.remove_policy("alice", "data1", "read")

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    async def test_async_cache_invalidate(self):
        e = casbin.AsyncCachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.invalidate_cache()
        await e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    async def test_async_enable_cache(self):
        e = casbin.AsyncCachedEnforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.enable_cache(False)
        await e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    async def test_async_g_function_cache(self):
        e = casbin.AsyncCachedEnforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        await e.load_policy()
        e.enable_g_function_cache(True)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))

        await e.add_grouping_policy("bob", "data2_admin")
        self.assertTrue(e.enforce("bob", "data2", "read"))
