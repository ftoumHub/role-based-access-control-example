package io.lombocska.app.security.bruteforce;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Adaptateur mémoire thread-safe, avec expiration. Réservé à une instance unique
 * (développement, tests) : les compteurs ne sont pas partagés.
 */
public class InMemoryAttemptCounterStore implements AttemptCounterStore {

	private record Counter(long count, Instant expiresAt) {
	}

	private final ConcurrentMap<String, Counter> counters = new ConcurrentHashMap<>();

	private final Clock clock;

	public InMemoryAttemptCounterStore(Clock clock) {
		this.clock = clock;
	}

	@Override
	public long increment(String key, Duration window) {
		Instant now = this.clock.instant();
		purgeExpired(now);
		return this.counters.compute(key, (k, current) -> (current == null || !current.expiresAt().isAfter(now))
				? new Counter(1, now.plus(window)) : new Counter(current.count() + 1, current.expiresAt()))
			.count();
	}

	@Override
	public long get(String key) {
		Counter counter = this.counters.get(key);
		return (counter != null && counter.expiresAt().isAfter(this.clock.instant())) ? counter.count() : 0L;
	}

	@Override
	public void reset(String key) {
		this.counters.remove(key);
	}

	private void purgeExpired(Instant now) {
		this.counters.values().removeIf((counter) -> !counter.expiresAt().isAfter(now));
	}

}
