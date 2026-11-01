package io.lombocska.app.account;

import java.time.Clock;
import java.time.Instant;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Traduit un {@link Account} en {@link UserDetails}, états de compte compris, et
 * ré-encode le mot de passe avec l'algorithme courant après une connexion réussie
 * ({@link UserDetailsPasswordService}).
 */
@Service
public class AccountUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

	private final AccountRepository accounts;

	private final Clock clock;

	public AccountUserDetailsService(AccountRepository accounts, Clock clock) {
		this.accounts = accounts;
		this.clock = clock;
	}

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) {
		Account account = this.accounts.findByEmailIgnoreCase(username)
			.orElseThrow(() -> new UsernameNotFoundException("Invalid username or password."));
		Instant now = this.clock.instant();
		return User.withUsername(account.getEmail())
			.password(account.getPassword())
			.authorities(account.getAuthorities().stream().map(Authority::getName).toArray(String[]::new))
			.disabled(!account.isEnabled())
			.accountLocked(account.isLockedAt(now))
			.accountExpired(account.isExpiredAt(now))
			.credentialsExpired(account.areCredentialsExpiredAt(now))
			.build();
	}

	@Override
	@Transactional
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		this.accounts.findByEmailIgnoreCase(user.getUsername())
			.ifPresent((account) -> account.changePassword(newPassword));
		return User.withUserDetails(user).password(newPassword).build();
	}

}
