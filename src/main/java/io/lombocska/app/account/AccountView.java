package io.lombocska.app.account;

import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/** Projection affichée dans les pages (aucun hash de mot de passe ne sort du domaine). */
public record AccountView(Long id, String userName, String email, Set<String> authorities, Instant lastLoginDate,
		boolean enabled, Instant lockedUntil) {

	static AccountView of(Account account) {
		return new AccountView(account.getId(), account.getUserName(), account.getEmail(),
				account.getAuthorities().stream().map(Authority::getName).collect(Collectors.toCollection(TreeSet::new)),
				account.getLastLoginDate(), account.isEnabled(), account.getLockedUntil());
	}

}
