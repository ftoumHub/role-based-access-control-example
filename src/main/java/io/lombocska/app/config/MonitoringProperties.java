package io.lombocska.app.config;

import jakarta.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Compte technique utilisé par Prometheus pour lire /actuator/prometheus (HTTP Basic). */
@Validated
@ConfigurationProperties("app.security.monitoring")
public record MonitoringProperties(@DefaultValue("prometheus") @NotBlank String username, @NotBlank String password) {
}
