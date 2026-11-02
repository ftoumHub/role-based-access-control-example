package io.lombocska.app.config;

import java.time.Clock;
import java.util.Map;

import io.lombocska.app.account.AccountService;
import io.lombocska.app.account.StatusEnforcingUserDetailsService;
import io.lombocska.app.security.bruteforce.AttemptCounterStore;
import io.lombocska.app.security.bruteforce.BruteForceProperties;
import io.lombocska.app.security.bruteforce.BruteForceProtection;
import io.lombocska.app.security.bruteforce.CaptchaVerificationFilter;
import io.lombocska.app.security.bruteforce.InMemoryAttemptCounterStore;
import io.lombocska.app.security.bruteforce.LoginFailureHandler;
import io.lombocska.app.security.bruteforce.RedisAttemptCounterStore;
import io.lombocska.app.security.captcha.CaptchaVerifier;
import io.lombocska.app.security.ott.LoggingMagicLinkSender;
import io.lombocska.app.security.ott.MagicLinkGenerationSuccessHandler;
import io.lombocska.app.security.ott.MagicLinkSender;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.ott.JdbcOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

/**
 * Configuration de sécurité (Spring Security 7).
 * <ol>
 * <li>Chaîne « management » : endpoints Actuator (port 8081), health public, le reste
 * réservé au compte technique de supervision en HTTP Basic, sans session.</li>
 * <li>Chaîne applicative : formulaire + CAPTCHA conditionnel vérifié avant
 * l'authentification, lien à usage unique, passkeys, MFA pour l'administration, CSRF
 * actif, déconnexion en POST.</li>
 * </ol>
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
@EnableMultiFactorAuthentication(authorities = {})
public class SecurityConfiguration {

	// ------------------------------------------------------------------ chaînes de filtres

	@Bean
	@Order(1)
	SecurityFilterChain managementSecurityFilterChain(HttpSecurity http, MonitoringProperties monitoring,
			PasswordEncoder passwordEncoder) throws Exception {
		UserDetailsService monitoringUsers = new InMemoryUserDetailsManager(User.withUsername(monitoring.username())
			.password(passwordEncoder.encode(monitoring.password()))
			.roles("MONITORING")
			.build());
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(monitoringUsers);
		provider.setPasswordEncoder(passwordEncoder);
		// @formatter:off
		http
			.securityMatcher(EndpointRequest.toAnyEndpoint())
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers(EndpointRequest.to("health")).permitAll()
				.anyRequest().hasRole("MONITORING"))
			// gestionnaire isolé : les comptes applicatifs ne peuvent pas s'authentifier ici
			.authenticationManager(new ProviderManager(provider))
			.httpBasic(Customizer.withDefaults())
			.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.csrf((csrf) -> csrf.disable());
		// @formatter:on
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain applicationSecurityFilterChain(HttpSecurity http, BruteForceProtection protection,
			CaptchaVerifier captchaVerifier, UserDetailsService userDetailsService,
			OneTimeTokenService oneTimeTokenService, AccountService accounts, MagicLinkSender magicLinkSender,
			WebAuthnProperties webAuthn) throws Exception {

		LoginFailureHandler failureHandler = new LoginFailureHandler(protection);
		// Les mécanismes sans mot de passe doivent eux aussi refuser les comptes verrouillés/désactivés.
		UserDetailsService passwordless = new StatusEnforcingUserDetailsService(userDetailsService);
		http.setSharedObject(UserDetailsService.class, passwordless); // lu par WebAuthnConfigurer

		// Administration : ROLE_ADMIN + (passkey) ou (mot de passe + lien à usage unique)
		AllRequiredFactorsAuthorizationManager<Object> passkey = AllRequiredFactorsAuthorizationManager.<Object>builder()
			.requireFactor((factor) -> factor.webauthnAuthority())
			.build();
		AllRequiredFactorsAuthorizationManager<Object> passwordAndOtt = AllRequiredFactorsAuthorizationManager
			.<Object>builder()
			.requireFactor((factor) -> factor.passwordAuthority())
			.requireFactor((factor) -> factor.ottAuthority())
			.build();
		DefaultAuthorizationManagerFactory<Object> mfa = new DefaultAuthorizationManagerFactory<>();
		mfa.setAdditionalAuthorization(AllRequiredFactorsAuthorizationManager.anyOf(passkey, passwordAndOtt));

		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/error").permitAll()
				.requestMatchers("/administration/**").access(mfa.hasRole("ADMIN"))
				.requestMatchers("/user/**").hasRole("USER")
				.requestMatchers("/content-editor/**").hasRole("EDITOR")
				.anyRequest().authenticated())
			.addFilterBefore(new CaptchaVerificationFilter(protection, captchaVerifier, failureHandler),
					UsernamePasswordAuthenticationFilter.class)
			.formLogin((form) -> form
				.loginPage("/login")
				.defaultSuccessUrl("/", false)
				.failureHandler(failureHandler)
				.permitAll())
			.oneTimeTokenLogin((ott) -> ott
				// page personnalisée : sinon la page de connexion générée par défaut reprend /login
				.loginPage("/login")
				.tokenService(oneTimeTokenService)
				.tokenGenerationSuccessHandler(new MagicLinkGenerationSuccessHandler(accounts, magicLinkSender))
				.authenticationProvider(new OneTimeTokenAuthenticationProvider(oneTimeTokenService, passwordless))
				.authenticationFailureHandler(failureHandler))
			.webAuthn((passkeys) -> passkeys
				.rpId(webAuthn.rpId())
				.rpName(webAuthn.rpName())
				.allowedOrigins(webAuthn.allowedOrigins()))
			.logout((logout) -> logout
				.logoutSuccessUrl("/login?logout")
				.deleteCookies("SESSION"));
		// @formatter:on
		return http.build();
	}

	// ------------------------------------------------------------------ mots de passe

	/**
	 * Encodage Argon2 pour tout nouveau hash ; les hash BCrypt historiques (sans préfixe)
	 * restent vérifiables et sont ré-encodés en Argon2 à la connexion suivante.
	 */
	@Bean
	PasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
		DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder("argon2",
				Map.of("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), "bcrypt", bcrypt));
		encoder.setDefaultPasswordEncoderForMatches(bcrypt);
		return encoder;
	}

	// ------------------------------------------------------------------ anti-force brute

	@Bean
	AttemptCounterStore attemptCounterStore(BruteForceProperties properties,
			ObjectProvider<StringRedisTemplate> redis, Clock clock) {
		return switch (properties.store()) {
			case REDIS -> new RedisAttemptCounterStore(redis.getObject());
			case MEMORY -> new InMemoryAttemptCounterStore(clock);
		};
	}

	@Bean
	BruteForceProtection bruteForceProtection(AttemptCounterStore store, BruteForceProperties properties,
			AccountService accounts, ApplicationEventPublisher events, Clock clock) {
		return new BruteForceProtection(store, properties, accounts, events, clock);
	}

	// ------------------------------------------------------------------ sans mot de passe

	@Bean
	OneTimeTokenService oneTimeTokenService(JdbcOperations jdbc) {
		return new JdbcOneTimeTokenService(jdbc);
	}

	@Bean
	MagicLinkSender magicLinkSender() {
		return new LoggingMagicLinkSender();
	}

	@Bean
	PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(JdbcOperations jdbc) {
		return new JdbcPublicKeyCredentialUserEntityRepository(jdbc);
	}

	@Bean
	UserCredentialRepository userCredentialRepository(JdbcOperations jdbc) {
		return new JdbcUserCredentialRepository(jdbc);
	}

	// ------------------------------------------------------------------ audit

	/** Publie les refus d'autorisation, journalisés par l'audit Actuator. */
	@Bean
	AuthorizationEventPublisher authorizationEventPublisher(ApplicationEventPublisher publisher) {
		return new SpringAuthorizationEventPublisher(publisher);
	}

}
