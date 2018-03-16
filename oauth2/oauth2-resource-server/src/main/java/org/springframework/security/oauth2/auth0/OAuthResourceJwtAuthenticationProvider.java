package org.springframework.security.oauth2.auth0;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.resource.authentication.OAuth2ResourceAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * An {@link AuthenticationProvider} implementation that verifies the provided
 * JWT and extracts the relevant claims to formulate the appropriate authorities.
 * <p>
 * This is dependent on auth0, however with a small amount of elbow grease, the
 * dependency could be abstracted away.
 */
public class OAuthResourceJwtAuthenticationProvider implements AuthenticationProvider {
	private final JwtVerifier jwtVerifier;

	public OAuthResourceJwtAuthenticationProvider(JwtVerifier jwtVerifier) {
		Assert.notNull(jwtVerifier, "jwtVerifier is required");
		this.jwtVerifier = jwtVerifier;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		if (authentication instanceof OAuth2ResourceAuthenticationToken) {
			OAuth2ResourceAuthenticationToken token = (OAuth2ResourceAuthenticationToken) authentication;

			try {
				DecodedJWT jwt = jwtVerifier.verify(token.getCredentials());

				List<GrantedAuthority> authorities =
					Optional.ofNullable(jwt.getClaim("scope"))
						.map(claim -> Arrays.asList(claim.asString().split(" ")))
						.orElse(Collections.emptyList())
						.stream()
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());

				return new UsernamePasswordAuthenticationToken(
					token.getPrincipal(),
					token.getCredentials(),
					authorities);

			} catch (TokenExpiredException e) {
				throw new CredentialsExpiredException("Failed to authenticate user", e);
			} catch (JWTVerificationException e) {
				throw new BadCredentialsException("Failed to authenticate user", e);
			}

		} else {
			return null;
		}
	}

	@Override
	public boolean supports(Class<?> type) {
		return OAuth2ResourceAuthenticationToken.class.isAssignableFrom(type);
	}
}
