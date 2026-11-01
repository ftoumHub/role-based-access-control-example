package io.lombocska.app.security.bruteforce;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;

import io.lombocska.app.account.AccountService;

import org.springframework.context.ApplicationEventPublisher;

/**
 * Protection contre la force brute, indépendante du mécanisme d'authentification.
 * <ul>
 * <li>deux compteurs : par compte (identifiant saisi) et par adresse IP réelle ;</li>
 * <li>CAPTCHA exigé dès que l'un des deux atteint {@code captchaThreshold} ;</li>
 * <li>verrouillage temporaire du compte à {@code lockThreshold} échecs ;</li>
 * <li>un succès ne remet à zéro que le compteur du compte : une IP qui teste beaucoup de
 * comptes ne peut pas « blanchir » son compteur avec un compte valide.</li>
 * </ul>
 */
public class BruteForceProtection {

	public record FailureOutcome(boolean captchaRequired, boolean accountLocked) {
	}

	private final AttemptCounterStore store;

	private final BruteForceProperties properties;

	private final AccountService accounts;

	private final ApplicationEventPublisher events;

	private final Clock clock;

	public BruteForceProtection(AttemptCounterStore store, BruteForceProperties properties, AccountService accounts,
			ApplicationEventPublisher events, Clock clock) {
		this.store = store;
		this.properties = properties;
		this.accounts = accounts;
		this.events = events;
		this.clock = clock;
	}

	public boolean isCaptchaRequired(String username, String ip) {
		return this.store.get(accountKey(username)) >= this.properties.captchaThreshold()
				|| this.store.get(ipKey(ip)) >= this.properties.captchaThreshold();
	}

	public boolean isCaptchaRequiredForIp(String ip) {
		return this.store.get(ipKey(ip)) >= this.properties.captchaThreshold();
	}

	public FailureOutcome recordFailure(String username, String ip) {
		long accountFailures = this.store.increment(accountKey(username), this.properties.window());
		long ipFailures = this.store.increment(ipKey(ip), this.properties.window());
		boolean locked = false;
		if (accountFailures >= this.properties.lockThreshold() && username != null && !username.isBlank()) {
			Instant until = this.clock.instant().plus(this.properties.lockDuration());
			locked = this.accounts.lockIfExists(username, until);
			if (locked) {
				this.events.publishEvent(new AccountLockedEvent(normalize(username), until, accountFailures));
			}
		}
		boolean captcha = accountFailures >= this.properties.captchaThreshold()
				|| ipFailures >= this.properties.captchaThreshold();
		return new FailureOutcome(captcha, locked);
	}

	public void recordSuccess(String username) {
		this.store.reset(accountKey(username));
	}

	private static String accountKey(String username) {
		return "account:" + normalize(username);
	}

	private static String ipKey(String ip) {
		return "ip:" + ((ip != null) ? ip : "unknown");
	}

	private static String normalize(String username) {
		return (username != null) ? username.trim().toLowerCase(Locale.ROOT) : "";
	}

}
