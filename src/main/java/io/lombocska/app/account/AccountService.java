package io.lombocska.app.account;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class AccountService {

	private final AccountRepository accounts;

	private final Clock clock;

	public AccountService(AccountRepository accounts, Clock clock) {
		this.accounts = accounts;
		this.clock = clock;
	}

	public List<AccountView> findAll() {
		return this.accounts.findAll().stream().map(AccountView::of).toList();
	}

	public Optional<AccountView> findByEmail(String email) {
		return this.accounts.findByEmailIgnoreCase(email).map(AccountView::of);
	}

	@Transactional
	public void recordSuccessfulLogin(String email) {
		this.accounts.findByEmailIgnoreCase(email).ifPresent((account) -> account.recordLogin(this.clock.instant()));
	}

	/**
	 * Verrouille temporairement le compte s'il existe.
	 * @return {@code true} si un compte a effectivement été verrouillé
	 */
	@Transactional
	public boolean lockIfExists(String email, Instant until) {
		return this.accounts.findByEmailIgnoreCase(email).map((account) -> {
			account.lockUntil(until);
			return true;
		}).orElse(false);
	}

}
