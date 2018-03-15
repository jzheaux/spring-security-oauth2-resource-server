package org.springframework.security.oauth2.jwt;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.function.Function;

/**
 * This is mostly just me playing around with a few ideas. I like what Joe did, too with OAuth2Error.
 */
public enum JwtError {
	EXPIRED("jwt.error.expired", "Jwt Expired At {}", Jwt::getExpiresAt),
	NOT_BEFORE("jwt.error.notBefore", "Jwt Used Too Early"),
	INVALID("jwt.error.invalid", "Jwt Invalid");

	private final String errorCode;
	private final String description;
	private final Function<Jwt, ?> contentResolver;

	JwtError(String errorCode, String description) {
		this(errorCode, description, (jwt) ->  null);
	}

	JwtError(String errorCode, String description, Function<Jwt, ?> contentResolver) {
		this.errorCode = errorCode;
		this.description = description;
		this.contentResolver = contentResolver;
	}

	public String getDescription() {
		return this.description;
	}

	public String getErrorCode() {
		return this.errorCode;
	}

	public String renderErrorMessage(Jwt jwt) {
		return String.format(this.description, this.contentResolver.apply(jwt));
	}
}
