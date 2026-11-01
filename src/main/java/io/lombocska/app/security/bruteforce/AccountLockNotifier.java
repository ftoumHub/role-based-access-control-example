package io.lombocska.app.security.bruteforce;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Réagit au verrouillage d'un compte. L'adaptateur actuel journalise et compte ; un envoi
 * d'email au titulaire se brancherait ici.
 */
@Component
public class AccountLockNotifier {

	private static final Logger log = LoggerFactory.getLogger(AccountLockNotifier.class);

	private final MeterRegistry meters;

	public AccountLockNotifier(MeterRegistry meters) {
		this.meters = meters;
	}

	@EventListener
	public void onAccountLocked(AccountLockedEvent event) {
		this.meters.counter("app.security.account.lockouts").increment();
		log.warn("Compte {} verrouillé jusqu'à {} après {} échecs de connexion", event.email(), event.lockedUntil(),
				event.failedAttempts());
	}

}
