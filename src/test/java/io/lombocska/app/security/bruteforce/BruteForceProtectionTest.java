package io.lombocska.app.security.bruteforce;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import io.lombocska.app.account.AccountService;
import io.lombocska.app.security.bruteforce.BruteForceProperties.Store;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BruteForceProtectionTest {

	private static final String IP = "203.0.113.7";

	private final MutableClock clock = new MutableClock(Instant.parse("2026-11-01T10:00:00Z"));

	private final AccountService accounts = mock(AccountService.class);

	private final ApplicationEventPublisher events = mock(ApplicationEventPublisher.class);

	private BruteForceProtection protection;

	@BeforeEach
	void setUp() {
		BruteForceProperties properties = new BruteForceProperties(3, 10, Duration.ofMinutes(15),
				Duration.ofMinutes(15), Store.MEMORY);
		this.protection = new BruteForceProtection(new InMemoryAttemptCounterStore(this.clock), properties,
				this.accounts, this.events, this.clock);
	}

	@Test
	void captchaIsRequiredAfterThreeFailuresOnTheSameAccount() {
		this.protection.recordFailure("user@test.com", "198.51.100.1");
		this.protection.recordFailure("USER@test.com", "198.51.100.2");
		assertThat(this.protection.isCaptchaRequired("user@test.com", "198.51.100.9")).isFalse();

		this.protection.recordFailure(" user@test.com ", "198.51.100.3");

		assertThat(this.protection.isCaptchaRequired("user@test.com", "198.51.100.9")).isTrue();
	}

	@Test
	void captchaIsRequiredAfterThreeFailuresFromTheSameIpAcrossAccounts() {
		this.protection.recordFailure("a@test.com", IP);
		this.protection.recordFailure("b@test.com", IP);
		this.protection.recordFailure("c@test.com", IP);

		assertThat(this.protection.isCaptchaRequired("d@test.com", IP)).isTrue();
		assertThat(this.protection.isCaptchaRequiredForIp(IP)).isTrue();
	}

	@Test
	void successResetsTheAccountCounterButNotTheIpCounter() {
		this.protection.recordFailure("a@test.com", IP);
		this.protection.recordFailure("a@test.com", IP);
		this.protection.recordFailure("a@test.com", IP);

		this.protection.recordSuccess("a@test.com");

		assertThat(this.protection.isCaptchaRequired("a@test.com", "198.51.100.1")).isFalse();
		assertThat(this.protection.isCaptchaRequiredForIp(IP)).isTrue();
	}

	@Test
	void countersExpireAfterTheWindow() {
		this.protection.recordFailure("a@test.com", IP);
		this.protection.recordFailure("a@test.com", IP);
		this.protection.recordFailure("a@test.com", IP);

		this.clock.advance(Duration.ofMinutes(16));

		assertThat(this.protection.isCaptchaRequired("a@test.com", IP)).isFalse();
	}

	@Test
	void accountIsLockedAtTheLockThreshold() {
		when(this.accounts.lockIfExists(eq("a@test.com"), any())).thenReturn(true);
		for (int i = 0; i < 9; i++) {
			assertThat(this.protection.recordFailure("a@test.com", IP).accountLocked()).isFalse();
		}

		BruteForceProtection.FailureOutcome outcome = this.protection.recordFailure("a@test.com", IP);

		assertThat(outcome.accountLocked()).isTrue();
		verify(this.accounts).lockIfExists("a@test.com", Instant.parse("2026-11-01T10:15:00Z"));
		verify(this.events).publishEvent(any(AccountLockedEvent.class));
	}

	@Test
	void unknownAccountsAreNotLockedButStillCounted() {
		when(this.accounts.lockIfExists(any(), any())).thenReturn(false);
		for (int i = 0; i < 10; i++) {
			this.protection.recordFailure("ghost@test.com", IP);
		}
		verify(this.events, never()).publishEvent(any(AccountLockedEvent.class));
		assertThat(this.protection.isCaptchaRequired("ghost@test.com", "198.51.100.1")).isTrue();
	}

	static final class MutableClock extends Clock {

		private Instant now;

		MutableClock(Instant now) {
			this.now = now;
		}

		void advance(Duration duration) {
			this.now = this.now.plus(duration);
		}

		@Override
		public ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return this.now;
		}

	}

}
