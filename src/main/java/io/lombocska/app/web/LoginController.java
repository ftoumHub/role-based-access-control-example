package io.lombocska.app.web;

import java.util.List;

import io.lombocska.app.security.bruteforce.BruteForceProtection;
import io.lombocska.app.security.captcha.RecaptchaProperties;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Page de connexion. Sert aussi de page de « facteur supplémentaire » : quand une règle
 * MFA refuse l'accès, Spring Security redirige ici avec {@code factor.type=ott},
 * {@code factor.type=webauthn}… et la page ne propose que les facteurs manquants.
 */
@Controller
public class LoginController {

	private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private final BruteForceProtection protection;

	private final RecaptchaProperties recaptcha;

	public LoginController(BruteForceProtection protection, RecaptchaProperties recaptcha) {
		this.protection = protection;
		this.recaptcha = recaptcha;
	}

	@GetMapping("/login")
	public String login(HttpServletRequest request, Authentication authentication, Model model) {
		String[] factors = request.getParameterValues("factor.type");
		List<String> factorTypes = (factors != null) ? List.of(factors) : List.of();
		boolean authenticated = this.trustResolver.isAuthenticated(authentication);
		model.addAttribute("secondFactor", authenticated && !factorTypes.isEmpty());
		model.addAttribute("offerPassword", factorTypes.isEmpty() || factorTypes.contains("password"));
		model.addAttribute("offerOtt", factorTypes.isEmpty() || factorTypes.contains("ott"));
		model.addAttribute("offerPasskey", factorTypes.isEmpty() || factorTypes.contains("webauthn"));
		model.addAttribute("captchaRequired", request.getParameter("captcha") != null
				|| this.protection.isCaptchaRequiredForIp(request.getRemoteAddr()));
		model.addAttribute("recaptchaSiteKey", this.recaptcha.siteKey());
		return "login";
	}

}
