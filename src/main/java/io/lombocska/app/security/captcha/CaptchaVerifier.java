package io.lombocska.app.security.captcha;

/** Port de vérification d'une réponse CAPTCHA. */
public interface CaptchaVerifier {

	boolean verify(String captchaResponse, String remoteIp);

}
