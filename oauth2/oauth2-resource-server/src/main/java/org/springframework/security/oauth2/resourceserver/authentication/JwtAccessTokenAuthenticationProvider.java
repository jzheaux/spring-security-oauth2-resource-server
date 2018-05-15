/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.resourceserver.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.AuthoritiesExtractor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;

/**
 * An {@link AuthenticationProvider} implementation of the OAuth2 Resource Server Bearer Token when using Jwt-encoding
 * <p>
 * <p>
 * This {@link AuthenticationProvider} is responsible for decoding and verifying a Jwt-encoded access token,
 * returning a Jwt claims set as part of the {@see Authentication} statement.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @since 5.1
 * @see JwtAccessTokenVerifier
 * @see AuthenticationProvider
 * @see JwtDecoder
 */
public class JwtAccessTokenAuthenticationProvider implements AuthenticationProvider {
	private final JwtDecoder jwtDecoder;
	private final JwtAccessTokenVerifier jwtVerifier;

	private AuthoritiesExtractor authoritiesExtractor = (authentication) -> Collections.emptyList();

	public JwtAccessTokenAuthenticationProvider(JwtDecoder jwtDecoder) {
		this(jwtDecoder, new JwtAccessTokenVerifier());
	}

	public JwtAccessTokenAuthenticationProvider(JwtDecoder jwtDecoder,
												JwtAccessTokenVerifier jwtVerifier) {
		Assert.notNull(jwtDecoder, "jwtDecoder is required");
		Assert.notNull(jwtVerifier, "jwtVerifier is required");

		this.jwtDecoder = jwtDecoder;
		this.jwtVerifier = jwtVerifier;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		PreAuthenticatedAuthenticationToken preAuthentication =
				(PreAuthenticatedAuthenticationToken) authentication;

		Jwt jwt;
		try {
			jwt = this.jwtDecoder.decode(String.valueOf(preAuthentication.getPrincipal()));
		} catch (JwtException failed) {
			OAuth2Error invalidRequest =
					new OAuth2Error(
							OAuth2ErrorCodes.INVALID_REQUEST,
							failed.getMessage(),
							"https://tools.ietf.org/html/rfc6750#section-3.1");

			throw new OAuth2AuthenticationException(invalidRequest, failed);
		}

		this.jwtVerifier.verify(jwt);

		Collection<? extends GrantedAuthority> authorities =
				this.authoritiesExtractor.extractAuthorities(new JwtAccessTokenAuthenticationToken(jwt));

		JwtAccessTokenAuthenticationToken token =
				new JwtAccessTokenAuthenticationToken(jwt, authorities);

		if ( jwt.getClaims().get("scp") != null ) {
			token.setScopeAttributeName("scp");
		}

		return token;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setAuthoritiesExtractor(AuthoritiesExtractor authoritiesExtractor) {
		Assert.notNull(authoritiesExtractor, "authoritiesExtractor cannot be null");
		this.authoritiesExtractor = authoritiesExtractor;
	}
}
