package io.lombocska.app.security.captcha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/** Adaptateur Google reCAPTCHA v2 (API siteverify). Échec fermé : toute erreur vaut refus. */
@Component
public class RecaptchaVerifier implements CaptchaVerifier {

	private static final Logger log = LoggerFactory.getLogger(RecaptchaVerifier.class);

	record SiteVerifyResponse(boolean success) {
	}

	private final RestClient restClient;

	private final RecaptchaProperties properties;

	public RecaptchaVerifier(RestClient.Builder builder, RecaptchaProperties properties) {
		this.restClient = builder.build();
		this.properties = properties;
	}

	@Override
	public boolean verify(String captchaResponse, String remoteIp) {
		if (!StringUtils.hasText(captchaResponse)) {
			return false;
		}
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("secret", this.properties.secretKey());
		form.add("response", captchaResponse);
		if (remoteIp != null) {
			form.add("remoteip", remoteIp);
		}
		try {
			SiteVerifyResponse response = this.restClient.post()
				.uri(this.properties.verificationUrl())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(form)
				.retrieve()
				.body(SiteVerifyResponse.class);
			return response != null && response.success();
		}
		catch (RestClientException ex) {
			log.warn("Vérification reCAPTCHA impossible : {}", ex.getMessage());
			return false;
		}
	}

}
