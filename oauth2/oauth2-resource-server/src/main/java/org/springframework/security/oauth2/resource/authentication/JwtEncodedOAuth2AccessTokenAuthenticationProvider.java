package org.springframework.security.oauth2.resource.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.bearer.OAuth2AccessTokenAuthority;
import org.springframework.security.oauth2.jwt.AccessTokenJwtVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtVerifier;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

/**
 * An {@link AuthenticationProvider} implementation of the OAuth2 Resource Server Bearer Token when using Jwt-encoding
 * <p>
 * <p>
 * This {@link AuthenticationProvider} is responsible for decoding and verifying a Jwt-encoded access token,
 * returning a Jwt claims set as part of the {@see Authentication} statement.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see AccessTokenJwtVerifier
 * @see AuthenticationProvider
 * @see JwtDecoder
 * @see JwtVerifier
 */
public class JwtEncodedOAuth2AccessTokenAuthenticationProvider implements AuthenticationProvider {
	private final JwtDecoder jwtDecoder;
	private final AccessTokenJwtVerifier jwtVerifier;

	private GrantedAuthoritiesMapper authoritiesMapper = authorities -> authorities;

	public JwtEncodedOAuth2AccessTokenAuthenticationProvider(JwtDecoder jwtDecoder) {
		this(jwtDecoder, new AccessTokenJwtVerifier());
	}

	public JwtEncodedOAuth2AccessTokenAuthenticationProvider(JwtDecoder jwtDecoder,
															 AccessTokenJwtVerifier jwtVerifier) {
		Assert.notNull(jwtDecoder, "jwtDecoder is required");
		Assert.notNull(jwtVerifier, "jwtVerifier is required");

		this.jwtDecoder = jwtDecoder;
		this.jwtVerifier = jwtVerifier;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof OAuth2ResourceAuthenticationToken) {
			OAuth2ResourceAuthenticationToken token = (OAuth2ResourceAuthenticationToken) authentication;

			Map<String, Object> claims = mapClaims(token);

			// OidcUserDetailsService does something similar to this, taking the claims set and
			// representing that as a single authority.
			Collection<? extends GrantedAuthority> authorities =
				Arrays.asList(new OAuth2AccessTokenAuthority(claims));

			// Here is where an end user can providing custom resolution of the OAtuh2AccessTokenAuthority,
			// including parsing the "scope" claim and converting that list into individual authorities
			authorities =
				this.authoritiesMapper.mapAuthorities(authorities);

			return new OAuth2ResourceAuthenticationToken(token.getPrincipal(), authorities);
		}

		return null;
	}

	/**
	 * Convert a Bearer token into a set of claims
	 *
	 * @param token
	 * @return
	 */
	protected Map<String, Object> mapClaims(OAuth2ResourceAuthenticationToken token) {
		Jwt jwt = this.jwtDecoder.decode(token.getPrincipal());

		this.jwtVerifier.verifyClaims(jwt);

		return jwt.getClaims();
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ResourceAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}
}
