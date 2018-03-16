package org.springframework.security.oauth2.jwt;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtError;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * This is still in flux. Joe and I talked about what should be propagated up to the Filter and whether it should be
 * an AuthenticationException or a custom one like OAuth2ResourceAuthenticationException or even an AccessDeniedException
 */
public class JwtVerificationException extends JwtException {
	private JwtError error;
	private Jwt jwt;

	public JwtVerificationException(JwtError error, String message) {
		super(message);
		this.error = error;
	}

	public JwtVerificationException(JwtError error, Jwt jwt) {
		this(error, error.renderErrorMessage(jwt));
		this.jwt = jwt;
	}

	public JwtError getError() {
		return this.error;
	}

	public Jwt getJwt() {
		return this.jwt;
	}
}
