package io.lombocska.app.support;

import io.lombocska.app.security.captcha.CaptchaVerifier;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** PostgreSQL et Redis réels pour les tests d'intégration, et un CAPTCHA factice. */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

	public static final String VALID_CAPTCHA = "valid-captcha";

	@Bean
	@ServiceConnection
	PostgreSQLContainer postgres() {
		return new PostgreSQLContainer("postgres:17-alpine");
	}

	@Bean
	@ServiceConnection(name = "redis")
	GenericContainer<?> redis() {
		return new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
	}

	@Bean
	@Primary
	CaptchaVerifier fakeCaptchaVerifier() {
		return (response, remoteIp) -> VALID_CAPTCHA.equals(response);
	}

}
