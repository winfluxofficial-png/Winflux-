"""Limitadores de taxa (token bucket) compartilhados por P2P e API. Puros: o relógio é injetável nos testes."""
import time


class TokenBucket:
    """`rate` tokens/s, até `burst` acumulados. `allow()` consome e diz se havia crédito."""

    __slots__ = ("rate", "burst", "tokens", "stamp", "_clock")

    def __init__(self, rate: float, burst: float, clock=time.monotonic):
        self.rate, self.burst, self._clock = float(rate), float(burst), clock
        self.tokens, self.stamp = float(burst), clock()

    def _refill(self) -> None:
        now = self._clock()
        self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now

    def allow(self, cost: float = 1.0) -> bool:
        self._refill()
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True

    def wait_time(self, cost: float = 1.0) -> float:
        """Segundos até haver crédito para `cost` (0 se já há)."""
        self._refill()
        return 0.0 if self.tokens >= cost else (cost - self.tokens) / self.rate


class KeyedLimiter:
    """Um balde por chave (ex.: IP). Memória limitada: acima de `max_keys`, descarta os mais ociosos."""

    def __init__(self, rate: float, burst: float, max_keys: int = 10_000, clock=time.monotonic):
        self.rate, self.burst, self.max_keys, self._clock = rate, burst, max_keys, clock
        self._b: dict = {}

    def allow(self, key, cost: float = 1.0) -> bool:
        b = self._b.get(key)
        if b is None:
            if len(self._b) >= self.max_keys:
                self._evict()
            b = self._b[key] = TokenBucket(self.rate, self.burst, self._clock)
        return b.allow(cost)

    def _evict(self) -> None:
        for k, _ in sorted(self._b.items(), key=lambda kv: kv[1].stamp)[: max(1, self.max_keys // 4)]:
            del self._b[k]

    def __len__(self) -> int:
        return len(self._b)
