package io.lombocska.app.config;

import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Partie de confiance (Relying Party) WebAuthn : domaine et origines autorisées. */
@Validated
@ConfigurationProperties("app.security.webauthn")
public record WebAuthnProperties(
		@DefaultValue("localhost") @NotBlank String rpId,
		@DefaultValue("RBAC example") @NotBlank String rpName,
		@DefaultValue("http://localhost:8080") @NotEmpty Set<String> allowedOrigins) {
}
