package io.lombocska.app.security.ott;

import java.io.IOException;
import java.net.URI;

import io.lombocska.app.account.AccountService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Envoie le lien uniquement si le compte existe, puis redirige toujours vers la même
 * page : la réponse ne permet pas de savoir si l'adresse correspond à un compte.
 */
public class MagicLinkGenerationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

	private final RedirectStrategy redirect = new DefaultRedirectStrategy();

	private final AccountService accounts;

	private final MagicLinkSender sender;

	public MagicLinkGenerationSuccessHandler(AccountService accounts, MagicLinkSender sender) {
		this.accounts = accounts;
		this.sender = sender;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken)
			throws IOException {
		String email = oneTimeToken.getUsername();
		if (this.accounts.findByEmail(email).isPresent()) {
			URI link = ServletUriComponentsBuilder.fromContextPath(request)
				.path("/login/ott")
				.queryParam("token", oneTimeToken.getTokenValue())
				.build()
				.toUri();
			this.sender.send(email, link);
		}
		this.redirect.sendRedirect(request, response, "/login/ott?sent");
	}

}
