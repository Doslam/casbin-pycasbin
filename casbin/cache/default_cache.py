import time

from casbin.cache import Cache, ErrNoSuchKey


class DefaultCache(Cache):
    def __init__(self):
        self._store = {}

    def set(self, key, value, *extra):
        ttl = extra[0] if extra else None
        expires_at = time.time() + ttl if ttl and ttl > 0 else None
        self._store[key] = (value, expires_at)

    def get(self, key):
        if key not in self._store:
            raise ErrNoSuchKey(key)
        value, expires_at = self._store[key]
        if expires_at and time.time() > expires_at:
            del self._store[key]
            raise ErrNoSuchKey(key)
        return value

    def delete(self, key):
        self._store.pop(key, None)

    def clear(self):
        self._store.clear()
