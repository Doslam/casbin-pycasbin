from casbin.synced_enforcer import SyncedEnforcer, RWLockWrite, AtomicBool
from casbin.cached_enforcer import CachedEnforcer


class SyncedCachedEnforcer(SyncedEnforcer):
    def __init__(self, model=None, adapter=None):
        self._e = CachedEnforcer(model, adapter)
        self._rwlock = RWLockWrite()
        self._rl = self._rwlock.gen_rlock()
        self._wl = self._rwlock.gen_wlock()
        self._auto_loading = AtomicBool(False)
        self._auto_loading_thread = None

    def enable_cache(self, enable):
        with self._wl:
            self._e.enable_cache(enable)

    def enable_g_function_cache(self, enabled):
        with self._wl:
            self._e.enable_g_function_cache(enabled)

    def invalidate_cache(self):
        with self._wl:
            self._e.invalidate_cache()

    def set_expire_time(self, expire_time):
        with self._wl:
            self._e.set_expire_time(expire_time)

    def set_cache(self, cache):
        with self._wl:
            self._e.set_cache(cache)
