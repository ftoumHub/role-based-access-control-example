package io.lombocska.app.security.bruteforce;

import io.lombocska.app.account.AccountService;
import io.micrometer.core.instrument.MeterRegistry;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

/**
 * Point unique de réaction aux événements d'authentification, quel que soit le
 * mécanisme (mot de passe, lien à usage unique, passkey) : compteurs anti-force brute,
 * date de dernière connexion et métriques Micrometer. L'audit persistant est assuré par
 * les listeners d'audit de Spring Boot Actuator (voir {@code JpaAuditEventRepository}).
 */
@Component
public class AuthenticationEventsListener {

	private final BruteForceProtection protection;

	private final AccountService accounts;

	private final MeterRegistry meters;

	public AuthenticationEventsListener(BruteForceProtection protection, AccountService accounts,
			MeterRegistry meters) {
		this.protection = protection;
		this.accounts = accounts;
		this.meters = meters;
	}

	@EventListener
	public void onSuccess(AuthenticationSuccessEvent event) {
		Authentication authentication = event.getAuthentication();
		this.protection.recordSuccess(authentication.getName());
		this.accounts.recordSuccessfulLogin(authentication.getName());
		this.meters.counter("app.security.authentication", "outcome", "success", "mechanism", mechanism(authentication))
			.increment();
	}

	@EventListener
	public void onFailure(AbstractAuthenticationFailureEvent event) {
		Authentication authentication = event.getAuthentication();
		if (event instanceof AuthenticationFailureBadCredentialsEvent) {
			this.protection.recordFailure(authentication.getName(), remoteAddress(authentication));
		}
		this.meters
			.counter("app.security.authentication", "outcome", "failure", "mechanism", mechanism(authentication),
					"reason", event.getException().getClass().getSimpleName())
			.increment();
	}

	private static String remoteAddress(Authentication authentication) {
		return (authentication.getDetails() instanceof WebAuthenticationDetails details) ? details.getRemoteAddress()
				: null;
	}

	private static String mechanism(Authentication authentication) {
		String type = authentication.getClass().getSimpleName();
		if (type.startsWith("UsernamePassword")) {
			return "password";
		}
		if (type.startsWith("OneTimeToken")) {
			return "one-time-token";
		}
		if (type.startsWith("WebAuthn")) {
			return "passkey";
		}
		return type;
	}

}
