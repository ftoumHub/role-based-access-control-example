package io.lombocska.app.security.bruteforce;

import java.time.Duration;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Politique anti-force brute.
 *
 * @param captchaThreshold nombre d'échecs (par compte ou par IP) à partir duquel le CAPTCHA est exigé
 * @param lockThreshold nombre d'échecs sur un compte déclenchant son verrouillage temporaire
 * @param window fenêtre glissante de comptage des échecs
 * @param lockDuration durée du verrouillage temporaire
 * @param store {@code redis} (partagé entre instances) ou {@code memory} (instance unique, tests)
 */
@Validated
@ConfigurationProperties("app.security.brute-force")
public record BruteForceProperties(
		@DefaultValue("3") @Min(1) int captchaThreshold,
		@DefaultValue("10") @Min(1) int lockThreshold,
		@DefaultValue("15m") @NotNull Duration window,
		@DefaultValue("15m") @NotNull Duration lockDuration,
		@DefaultValue("redis") @NotNull Store store) {

	public enum Store {

		REDIS, MEMORY

	}

}
