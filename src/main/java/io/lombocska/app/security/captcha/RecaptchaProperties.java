package io.lombocska.app.security.captcha;

import java.net.URI;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Clés Google reCAPTCHA v2. Aucune valeur par défaut pour les clés : l'application refuse
 * de démarrer si elles ne sont pas fournies (variables RECAPTCHA_SITE_KEY / RECAPTCHA_SECRET_KEY,
 * ou profil {@code dev} qui utilise les clés de test publiques de Google).
 */
@Validated
@ConfigurationProperties("app.security.recaptcha")
public record RecaptchaProperties(
		@NotBlank String siteKey,
		@NotBlank String secretKey,
		@DefaultValue("https://www.google.com/recaptcha/api/siteverify") @NotNull URI verificationUrl) {
}
