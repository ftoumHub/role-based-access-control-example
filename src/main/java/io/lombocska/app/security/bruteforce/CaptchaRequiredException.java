package io.lombocska.app.security.bruteforce;

import org.springframework.security.core.AuthenticationException;

public class CaptchaRequiredException extends AuthenticationException {

	public CaptchaRequiredException(String message) {
		super(message);
	}

}
