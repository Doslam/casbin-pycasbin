from abc import ABC, abstractmethod


class ErrNoSuchKey(LookupError):
    pass


class Cache(ABC):
    @abstractmethod
    def set(self, key, value, *extra):
        pass

    @abstractmethod
    def get(self, key):
        pass

    @abstractmethod
    def delete(self, key):
        pass

    @abstractmethod
    def clear(self):
        pass
