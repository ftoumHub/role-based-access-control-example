package io.lombocska.app.security.ott;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adaptateur de développement : écrit le lien dans les logs. À remplacer par un envoi
 * d'email (spring-boot-starter-mail) en dehors du développement.
 */
public class LoggingMagicLinkSender implements MagicLinkSender {

	private static final Logger log = LoggerFactory.getLogger(LoggingMagicLinkSender.class);

	@Override
	public void send(String email, URI magicLink) {
		log.info("[DEV] Lien de connexion pour {} : {}", email, magicLink);
	}

}
