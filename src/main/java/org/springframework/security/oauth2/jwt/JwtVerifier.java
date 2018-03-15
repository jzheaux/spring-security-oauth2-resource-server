package org.springframework.security.oauth2.jwt;

/**
 * Implementations of this interface are responsible for &quot;verifying&quot;
 * a JSON Web Token's (JWT) claims set
 *
 * <p>
 * Generally speaking, custom implementations of this contract should be wired as delegates to standard implementations
 * like {@see AccessTokenJwtVerifier}.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see Jwt
 * @see AccessTokenJwtVerifier
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 */
public interface JwtVerifier {
	void verifyClaims(Jwt jwt) throws JwtException;
}
