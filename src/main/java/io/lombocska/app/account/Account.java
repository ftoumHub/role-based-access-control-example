package io.lombocska.app.account;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

/**
 * Compte local. Les états (activé, verrouillé, expiré, mot de passe expiré) sont
 * portés en base et traduits en {@link org.springframework.security.core.userdetails.UserDetails}.
 */
@Entity
@Table(name = "account")
public class Account {

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequenceGenerator")
	@SequenceGenerator(name = "sequenceGenerator", sequenceName = "sequence_generator", allocationSize = 50)
	private Long id;

	@Column(name = "user_name", length = 50)
	private String userName;

	@Column(name = "email", length = 191, unique = true, nullable = false)
	private String email;

	/** Hash préfixé par l'identifiant d'algorithme ({argon2}, {bcrypt}…) ou hash BCrypt historique. */
	@Column(name = "password", length = 255, nullable = false)
	private String password;

	@Column(name = "enabled", nullable = false)
	private boolean enabled = true;

	@Column(name = "locked_until")
	private Instant lockedUntil;

	@Column(name = "account_expires_at")
	private Instant accountExpiresAt;

	@Column(name = "credentials_expire_at")
	private Instant credentialsExpireAt;

	@Column(name = "last_login_date")
	private Instant lastLoginDate;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "account_authority",
			joinColumns = @JoinColumn(name = "account_id", referencedColumnName = "id"),
			inverseJoinColumns = @JoinColumn(name = "authority_name", referencedColumnName = "name"))
	private Set<Authority> authorities = new HashSet<>();

	protected Account() {
	}

	public Account(String email, String userName, String password, Set<Authority> authorities) {
		this.email = email;
		this.userName = userName;
		this.password = password;
		this.authorities = new HashSet<>(authorities);
	}

	public boolean isLockedAt(Instant now) {
		return this.lockedUntil != null && this.lockedUntil.isAfter(now);
	}

	public boolean isExpiredAt(Instant now) {
		return this.accountExpiresAt != null && !this.accountExpiresAt.isAfter(now);
	}

	public boolean areCredentialsExpiredAt(Instant now) {
		return this.credentialsExpireAt != null && !this.credentialsExpireAt.isAfter(now);
	}

	public void lockUntil(Instant until) {
		this.lockedUntil = until;
	}

	public void changePassword(String encodedPassword) {
		this.password = encodedPassword;
	}

	public void recordLogin(Instant at) {
		this.lastLoginDate = at;
	}

	public void disable() {
		this.enabled = false;
	}

	public void expireAccountAt(Instant at) {
		this.accountExpiresAt = at;
	}

	public void expireCredentialsAt(Instant at) {
		this.credentialsExpireAt = at;
	}

	public Long getId() {
		return this.id;
	}

	public String getUserName() {
		return this.userName;
	}

	public String getEmail() {
		return this.email;
	}

	public String getPassword() {
		return this.password;
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public Instant getLockedUntil() {
		return this.lockedUntil;
	}

	public Instant getAccountExpiresAt() {
		return this.accountExpiresAt;
	}

	public Instant getCredentialsExpireAt() {
		return this.credentialsExpireAt;
	}

	public Instant getLastLoginDate() {
		return this.lastLoginDate;
	}

	public Set<Authority> getAuthorities() {
		return this.authorities;
	}

}
