package io.lombocska.app;

import java.util.List;

import io.lombocska.app.support.TestcontainersConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Tests d'intégration du plateau P1 : PostgreSQL et Redis réels (Testcontainers),
 * schéma Liquibase et comptes de démonstration (mot de passe « test »).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class SecurityIT {

	static final String USER = "user3@test.com"; // ROLE_USER

	static final String EDITOR = "user2@test.com"; // ROLE_EDITOR

	static final String PASSWORD = "test";

	@Autowired
	MockMvc mvc;

	@Autowired
	JdbcTemplate jdbc;

	@Autowired
	StringRedisTemplate redis;

	@BeforeEach
	void resetState() {
		this.redis.delete(this.redis.keys("rbac:login-attempts:*"));
		this.jdbc.update("update account set locked_until = null, enabled = true");
		this.jdbc.update("delete from audit_event");
		this.jdbc.update("delete from one_time_tokens");
	}

	// ------------------------------------------------------------------ helpers

	MockHttpServletRequestBuilder login(String username, String password, String ip) {
		return post("/login").param("username", username)
			.param("password", password)
			.with(csrf())
			.with((request) -> {
				request.setRemoteAddr(ip);
				return request;
			});
	}

	String redirectOf(MockHttpServletRequestBuilder request) throws Exception {
		MvcResult result = this.mvc.perform(request).andExpect(status().is3xxRedirection()).andReturn();
		return result.getResponse().getRedirectedUrl();
	}

	static UsernamePasswordAuthenticationToken admin(String... factors) {
		List<GrantedAuthority> authorities = new java.util.ArrayList<>();
		authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		for (String factor : factors) {
			authorities.add(FactorGrantedAuthority.fromAuthority(factor));
		}
		return UsernamePasswordAuthenticationToken.authenticated("admin@admin.com", null, authorities);
	}

	// ------------------------------------------------------------------ mot de passe

	@Nested
	class PasswordLogin {

		@Test
		void validPasswordRedirectsToHomeAndRecordsLogin() throws Exception {
			assertThat(redirectOf(login(USER, PASSWORD, "10.1.0.1"))).isEqualTo("/");
			assertThat(SecurityIT.this.jdbc.queryForObject(
					"select last_login_date is not null from account where email = ?", Boolean.class, USER))
				.isTrue();
		}

		@Test
		void legacyBcryptHashIsUpgradedToArgon2OnLogin() throws Exception {
			redirectOf(login(EDITOR, PASSWORD, "10.1.0.2"));
			String hash = SecurityIT.this.jdbc.queryForObject("select password from account where email = ?",
					String.class, EDITOR);
			assertThat(hash).startsWith("{argon2}");
			// et le nouveau hash fonctionne
			assertThat(redirectOf(login(EDITOR, PASSWORD, "10.1.0.2"))).isEqualTo("/");
		}

		@Test
		void loginWithoutCsrfTokenIsRejected() throws Exception {
			SecurityIT.this.mvc.perform(post("/login").param("username", USER).param("password", PASSWORD))
				.andExpect(status().isForbidden());
		}

		@Test
		void failedLoginIsAudited() throws Exception {
			redirectOf(login(USER, "wrong", "10.1.0.3"));
			assertThat(SecurityIT.this.jdbc.queryForObject(
					"select count(*) from audit_event where type = 'AUTHENTICATION_FAILURE' and principal = ? and remote_address = '10.1.0.3'",
					Integer.class, USER))
				.isEqualTo(1);
		}

	}

	// ------------------------------------------------------------------ anti-force brute

	@Nested
	class BruteForce {

		@Test
		void captchaIsRequiredAfterThreeFailuresAndCheckedBeforeAuthentication() throws Exception {
			String ip = "10.2.0.1";
			redirectOf(login(USER, "wrong", ip));
			redirectOf(login(USER, "wrong", ip));
			assertThat(redirectOf(login(USER, "wrong", ip))).isEqualTo("/login?error=credentials&captcha");

			// bon mot de passe mais pas de CAPTCHA : refusé avant toute authentification
			assertThat(redirectOf(login(USER, PASSWORD, ip))).isEqualTo("/login?error=captcha&captcha");
			// bon mot de passe et CAPTCHA valide : accepté
			assertThat(redirectOf(login(USER, PASSWORD, ip).param("g-recaptcha-response",
					TestcontainersConfiguration.VALID_CAPTCHA)))
				.isEqualTo("/");
		}

		@Test
		void forgedForwardedForHeaderDoesNotResetTheIpCounter() throws Exception {
			String ip = "10.2.0.2";
			for (String target : List.of("a@test.com", "b@test.com", "c@test.com")) {
				redirectOf(login(target, "wrong", ip).header("X-Forwarded-For", "198.51.100." + target.charAt(0)));
			}
			assertThat(redirectOf(login(USER, PASSWORD, ip).header("X-Forwarded-For", "198.51.100.200")))
				.startsWith("/login?error=captcha");
		}

		@Test
		void accountIsLockedAfterTenFailures() throws Exception {
			String ip = "10.2.0.3";
			for (int i = 0; i < 10; i++) {
				redirectOf(login(USER, "wrong", ip).param("g-recaptcha-response",
						TestcontainersConfiguration.VALID_CAPTCHA));
			}
			assertThat(SecurityIT.this.jdbc.queryForObject(
					"select locked_until is not null from account where email = ?", Boolean.class, USER))
				.isTrue();
			assertThat(redirectOf(login(USER, PASSWORD, ip).param("g-recaptcha-response",
					TestcontainersConfiguration.VALID_CAPTCHA)))
				.startsWith("/login?error=locked");
		}

	}

	// ------------------------------------------------------------------ lien à usage unique

	@Nested
	class OneTimeToken {

		String generateToken(String username) throws Exception {
			assertThat(redirectOf(post("/ott/generate").param("username", username).with(csrf())))
				.isEqualTo("/login/ott?sent");
			return SecurityIT.this.jdbc.queryForObject("select token_value from one_time_tokens where username = ?",
					String.class, username);
		}

		@Test
		void tokenLogsTheUserIn() throws Exception {
			String token = generateToken(USER);
			assertThat(redirectOf(post("/login/ott").param("token", token).with(csrf()))).isEqualTo("/");
		}

		@Test
		void lockedAccountCannotUseATokenEither() throws Exception {
			SecurityIT.this.jdbc.update("update account set locked_until = now() + interval '1 hour' where email = ?",
					USER);
			String token = generateToken(USER);
			assertThat(redirectOf(post("/login/ott").param("token", token).with(csrf())))
				.startsWith("/login?error=locked");
		}

		@Test
		void unknownAddressGetsTheSameResponse() throws Exception {
			assertThat(redirectOf(post("/ott/generate").param("username", "nobody@test.com").with(csrf())))
				.isEqualTo("/login/ott?sent");
		}

	}

	// ------------------------------------------------------------------ autorisations et MFA

	@Nested
	class Authorization {

		@Test
		void anonymousUserIsSentToLogin() throws Exception {
			assertThat(redirectOf(get("/account"))).endsWith("/login");
		}

		@Test
		void userRole() throws Exception {
			SecurityIT.this.mvc.perform(get("/user").with(user(USER).roles("USER"))).andExpect(status().isOk());
			SecurityIT.this.mvc.perform(get("/content-editor").with(user(USER).roles("USER")))
				.andExpect(status().isForbidden());
		}

		@Test
		void editorRole() throws Exception {
			SecurityIT.this.mvc.perform(get("/content-editor").with(user(EDITOR).roles("EDITOR")))
				.andExpect(status().isOk());
			SecurityIT.this.mvc.perform(get("/user").with(user(EDITOR).roles("EDITOR")))
				.andExpect(status().isForbidden());
		}

		@Test
		void nonAdminCannotReachAdministration() throws Exception {
			int status = SecurityIT.this.mvc.perform(get("/administration/accounts").with(user(USER).roles("USER")))
				.andReturn()
				.getResponse()
				.getStatus();
			assertThat(status).isNotEqualTo(200);
		}

		@Test
		void adminWithPasswordOnlyIsAskedForASecondFactor() throws Exception {
			String redirect = redirectOf(get("/administration/accounts")
				.with(authentication(admin(FactorGrantedAuthority.PASSWORD_AUTHORITY))));
			assertThat(redirect).contains("/login").contains("factor.type");
		}

		@Test
		void adminWithPasswordAndOneTimeTokenIsAllowed() throws Exception {
			SecurityIT.this.mvc
				.perform(get("/administration/accounts").with(authentication(
						admin(FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY))))
				.andExpect(status().isOk())
				.andExpect(view().name("administration-page"));
		}

		@Test
		void adminWithPasskeyIsAllowed() throws Exception {
			SecurityIT.this.mvc
				.perform(get("/administration/accounts")
					.with(authentication(admin(FactorGrantedAuthority.WEBAUTHN_AUTHORITY))))
				.andExpect(status().isOk());
		}

		@Test
		void logoutRequiresPost() throws Exception {
			// pas de page de déconnexion générée, et GET ne déconnecte pas
			SecurityIT.this.mvc.perform(get("/logout").with(user(USER).roles("USER")))
				.andExpect(status().isNotFound());
			assertThat(redirectOf(post("/logout").with(user(USER).roles("USER")).with(csrf())))
				.isEqualTo("/login?logout");
		}

	}

	// ------------------------------------------------------------------ pages publiques et Actuator

	@Nested
	class PublicResourcesAndActuator {

		@Test
		void loginPageAndPasskeyScriptAreServed() throws Exception {
			SecurityIT.this.mvc.perform(get("/login")).andExpect(status().isOk()).andExpect(view().name("login"));
			SecurityIT.this.mvc.perform(get("/login/webauthn.js")).andExpect(status().isOk());
		}

		@Test
		void healthIsPublic() throws Exception {
			SecurityIT.this.mvc.perform(get("/actuator/health")).andExpect(status().isOk());
		}

		@Test
		void prometheusRequiresTheMonitoringAccount() throws Exception {
			SecurityIT.this.mvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
			SecurityIT.this.mvc.perform(get("/actuator/prometheus").with(httpBasic(USER, PASSWORD)))
				.andExpect(status().isUnauthorized());
			SecurityIT.this.mvc.perform(get("/actuator/prometheus").with(httpBasic("prometheus", "test-monitoring")))
				.andExpect(status().isOk());
		}

		@Test
		void sensitiveEndpointsAreNotExposed() throws Exception {
			int status = SecurityIT.this.mvc
				.perform(get("/actuator/env").with(httpBasic("prometheus", "test-monitoring")))
				.andReturn()
				.getResponse()
				.getStatus();
			assertThat(status).isNotEqualTo(200);
		}

	}

}
