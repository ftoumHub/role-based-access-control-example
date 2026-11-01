package io.lombocska.app.security.ott;

import java.net.URI;

/** Port d'envoi du lien de connexion à usage unique au titulaire du compte. */
public interface MagicLinkSender {

	void send(String email, URI magicLink);

}
