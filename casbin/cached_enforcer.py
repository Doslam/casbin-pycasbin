from casbin.cache import Cache, ErrNoSuchKey
from casbin.cache.default_cache import DefaultCache
from casbin.enforcer import Enforcer


class CachedEnforcer(Enforcer):
    def __init__(self, *args, **kwargs):
        self._enable_cache = True
        self._cache = DefaultCache()
        self._expire_time = None
        super().__init__(*args, **kwargs)

    def enable_cache(self, enable_cache):
        self._enable_cache = enable_cache

    def set_expire_time(self, expire_time):
        self._expire_time = expire_time

    def set_cache(self, cache):
        self._cache = cache

    def invalidate_cache(self):
        self._cache.clear()

    @staticmethod
    def get_cache_key(*params):
        parts = []
        for p in params:
            if isinstance(p, str):
                parts.append(p)
            elif hasattr(p, "get_cache_key"):
                parts.append(p.get_cache_key())
            else:
                return None
            parts.append("$$")
        return "".join(parts)

    def enforce(self, *rvals):
        if not self._enable_cache:
            return super().enforce(*rvals)

        key = self.get_cache_key(*rvals)
        if key is None:
            return super().enforce(*rvals)

        try:
            return self._cache.get(key)
        except ErrNoSuchKey:
            pass

        result = super().enforce(*rvals)
        self._cache.set(key, result, self._expire_time)
        return result

    def load_policy(self):
        self.invalidate_cache()
        return super().load_policy()

    def clear_policy(self):
        self.invalidate_cache()
        return super().clear_policy()

    def _add_policy(self, sec, ptype, rule):
        self.invalidate_cache()
        return super()._add_policy(sec, ptype, rule)

    def _add_policies(self, sec, ptype, rules):
        self.invalidate_cache()
        return super()._add_policies(sec, ptype, rules)

    def _add_policies_ex(self, sec, ptype, rules):
        self.invalidate_cache()
        return super()._add_policies_ex(sec, ptype, rules)

    def _update_policy(self, sec, ptype, old_rule, new_rule):
        self.invalidate_cache()
        return super()._update_policy(sec, ptype, old_rule, new_rule)

    def _update_policies(self, sec, ptype, old_rules, new_rules):
        self.invalidate_cache()
        return super()._update_policies(sec, ptype, old_rules, new_rules)

    def _update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        self.invalidate_cache()
        return super()._update_filtered_policies(sec, ptype, new_rules, field_index, *field_values)

    def _remove_policy(self, sec, ptype, rule):
        self.invalidate_cache()
        return super()._remove_policy(sec, ptype, rule)

    def _remove_policies(self, sec, ptype, rules):
        self.invalidate_cache()
        return super()._remove_policies(sec, ptype, rules)

    def _remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        self.invalidate_cache()
        return super()._remove_filtered_policy(sec, ptype, field_index, *field_values)

    def _remove_filtered_policy_returns_effects(self, sec, ptype, field_index, *field_values):
        self.invalidate_cache()
        return super()._remove_filtered_policy_returns_effects(sec, ptype, field_index, *field_values)
