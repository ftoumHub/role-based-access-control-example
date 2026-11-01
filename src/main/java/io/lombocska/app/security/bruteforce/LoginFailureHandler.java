package io.lombocska.app.security.bruteforce;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Redirige vers la page de connexion avec un code d'erreur, et ajoute {@code captcha}
 * lorsque la prochaine tentative devra présenter un CAPTCHA. Les échecs sont comptés par
 * {@link AuthenticationEventsListener}, qui reçoit l'événement avant l'appel de ce handler.
 */
public class LoginFailureHandler implements AuthenticationFailureHandler {

	private final RedirectStrategy redirect = new DefaultRedirectStrategy();

	private final BruteForceProtection protection;

	public LoginFailureHandler(BruteForceProtection protection) {
		this.protection = protection;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		String url = "/login?error=" + reason(exception);
		if (this.protection.isCaptchaRequired(request.getParameter("username"), request.getRemoteAddr())) {
			url += "&captcha";
		}
		this.redirect.sendRedirect(request, response, url);
	}

	private static String reason(AuthenticationException exception) {
		if (exception instanceof LockedException) {
			return "locked";
		}
		if (exception instanceof DisabledException) {
			return "disabled";
		}
		if (exception instanceof AccountExpiredException) {
			return "expired";
		}
		if (exception instanceof CredentialsExpiredException) {
			return "credentials-expired";
		}
		if (exception instanceof CaptchaRequiredException) {
			return "captcha";
		}
		return "credentials";
	}

}
