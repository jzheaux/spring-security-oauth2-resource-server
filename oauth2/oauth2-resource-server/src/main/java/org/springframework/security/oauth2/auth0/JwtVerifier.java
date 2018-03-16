package org.springframework.security.oauth2.auth0;

import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * A contract intended to add an extension point to {@link com.auth0.jwt.JWTVerifier}.
 * <p>
 * Since {@link com.auth0.jwt.JWTVerifier} is final, it can't be decorated, mocked, or
 * otherwise extended. This interface is used in the app instead in order to provide the
 * above flexibility.
 */
@FunctionalInterface
public interface JwtVerifier {
	/**
	 * {@see com.auth0.jwt.JWTVerifier#verify}
	 *
	 * @param token
	 * @return
	 */
	DecodedJWT verify(String token);
}
