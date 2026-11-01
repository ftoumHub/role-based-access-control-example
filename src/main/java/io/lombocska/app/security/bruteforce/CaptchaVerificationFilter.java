package io.lombocska.app.security.bruteforce;

import java.io.IOException;

import io.lombocska.app.security.captcha.CaptchaVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Vérifie le CAPTCHA <strong>avant</strong> toute tentative d'authentification par
 * mot de passe, lorsque le compte ou l'IP a dépassé le seuil. Placé avant
 * {@code UsernamePasswordAuthenticationFilter} : aucune session authentifiée ne peut
 * exister sans CAPTCHA valide. L'IP utilisée est {@code getRemoteAddr()}, que Tomcat ne
 * réécrit à partir de X-Forwarded-For que pour les proxys déclarés de confiance.
 */
public class CaptchaVerificationFilter extends OncePerRequestFilter {

	public static final String CAPTCHA_PARAMETER = "g-recaptcha-response";

	private final RequestMatcher loginRequest = PathPatternRequestMatcher.withDefaults()
		.matcher(HttpMethod.POST, "/login");

	private final BruteForceProtection protection;

	private final CaptchaVerifier verifier;

	private final AuthenticationFailureHandler failureHandler;

	public CaptchaVerificationFilter(BruteForceProtection protection, CaptchaVerifier verifier,
			AuthenticationFailureHandler failureHandler) {
		this.protection = protection;
		this.verifier = verifier;
		this.failureHandler = failureHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (this.loginRequest.matches(request)) {
			String username = request.getParameter("username");
			String ip = request.getRemoteAddr();
			if (this.protection.isCaptchaRequired(username, ip)
					&& !this.verifier.verify(request.getParameter(CAPTCHA_PARAMETER), ip)) {
				this.failureHandler.onAuthenticationFailure(request, response,
						new CaptchaRequiredException("Missing or invalid CAPTCHA"));
				return;
			}
		}
		chain.doFilter(request, response);
	}

}
