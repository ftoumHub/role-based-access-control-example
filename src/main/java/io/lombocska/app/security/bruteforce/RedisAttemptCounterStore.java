package io.lombocska.app.security.bruteforce;

import java.time.Duration;
import java.util.List;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

/** Adaptateur Redis : INCR + PEXPIRE atomiques via un script Lua. */
public class RedisAttemptCounterStore implements AttemptCounterStore {

	private static final String PREFIX = "rbac:login-attempts:";

	private static final RedisScript<Long> INCREMENT = new DefaultRedisScript<>("""
			local count = redis.call('INCR', KEYS[1])
			if count == 1 then
			  redis.call('PEXPIRE', KEYS[1], ARGV[1])
			end
			return count
			""", Long.class);

	private final StringRedisTemplate redis;

	public RedisAttemptCounterStore(StringRedisTemplate redis) {
		this.redis = redis;
	}

	@Override
	public long increment(String key, Duration window) {
		Long count = this.redis.execute(INCREMENT, List.of(PREFIX + key), String.valueOf(window.toMillis()));
		return (count != null) ? count : 0L;
	}

	@Override
	public long get(String key) {
		String value = this.redis.opsForValue().get(PREFIX + key);
		return (value != null) ? Long.parseLong(value) : 0L;
	}

	@Override
	public void reset(String key) {
		this.redis.delete(PREFIX + key);
	}

}
