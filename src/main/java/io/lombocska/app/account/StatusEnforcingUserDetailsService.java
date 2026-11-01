package io.lombocska.app.account;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Décorateur utilisé par les mécanismes sans mot de passe (lien à usage unique, passkey).
 * <p>
 * Dans Spring Security 7.1, {@code OneTimeTokenAuthenticationProvider} et
 * {@code WebAuthnAuthenticationProvider} chargent l'utilisateur sans vérifier l'état du
 * compte : un compte verrouillé ou désactivé pourrait donc se connecter par ces voies.
 * Ce décorateur lève l'exception adéquate au chargement. L'expiration du mot de passe
 * n'est volontairement pas contrôlée ici, puisqu'aucun mot de passe n'est utilisé.
 */
public class StatusEnforcingUserDetailsService implements UserDetailsService {

	private final UserDetailsService delegate;

	public StatusEnforcingUserDetailsService(UserDetailsService delegate) {
		this.delegate = delegate;
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		UserDetails user = this.delegate.loadUserByUsername(username);
		if (!user.isAccountNonLocked()) {
			throw new LockedException("User account is locked");
		}
		if (!user.isEnabled()) {
			throw new DisabledException("User is disabled");
		}
		if (!user.isAccountNonExpired()) {
			throw new AccountExpiredException("User account has expired");
		}
		return user;
	}

}
