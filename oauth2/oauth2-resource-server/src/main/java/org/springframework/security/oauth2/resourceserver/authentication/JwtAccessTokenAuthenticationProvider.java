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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthoritiesPopulator;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidationResult;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;

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
 * @see JwtTimestampsValidator
 * @see AuthenticationProvider
 * @see JwtDecoder
 */
public class JwtAccessTokenAuthenticationProvider implements AuthenticationProvider {
	private final JwtDecoder jwtDecoder;

	private final OAuth2TokenValidator<Jwt> validator;

	private AuthoritiesPopulator authoritiesPopulator = new JwtAuthoritiesPopulator();

	public JwtAccessTokenAuthenticationProvider(JwtDecoder jwtDecoder) {
		this(jwtDecoder, Arrays.asList(new JwtTimestampsValidator()));
	}

	public JwtAccessTokenAuthenticationProvider(JwtDecoder jwtDecoder,
												Collection<OAuth2TokenValidator<Jwt>> validators) {
		Assert.notNull(jwtDecoder, "jwtDecoder is required");
		Assert.notEmpty(validators, "validators cannot be empty");

		this.jwtDecoder = jwtDecoder;

		OAuth2TokenValidator<Jwt> delegate = new DelegatingOAuth2TokenValidator<>(validators);
		if ( hasValidatorOfType(validators, JwtTimestampsValidator.class) ) {
			this.validator = delegate;
		} else {
			this.validator = new DelegatingOAuth2TokenValidator<>(new JwtTimestampsValidator(), delegate);
		}
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		BearerTokenAuthenticationToken bearer =
				(BearerTokenAuthenticationToken) authentication;

		Jwt jwt;
		try {
			jwt = this.jwtDecoder.decode(String.valueOf(bearer.getToken()));
		} catch (JwtException failed) {
			OAuth2Error invalidRequest = invalidRequest(failed.getMessage());
			throw new OAuth2AuthenticationException(invalidRequest, failed);
		}

		OAuth2TokenValidationResult result = this.validator.validate(jwt);

		if ( !result.isSuccess() ) {
			OAuth2Error error = invalidRequest(result.getFailureReasons());
			throw new OAuth2AuthenticationException(error, error.toString());
		}

		Authentication token =
				this.authoritiesPopulator.populateAuthorities(new JwtAccessTokenAuthenticationToken(jwt));

		if ( token instanceof AbstractAuthenticationToken ) {
			((AbstractAuthenticationToken) token).setDetails(bearer.getDetails());
		}

		return token;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setAuthoritiesPopulator(AuthoritiesPopulator authoritiesPopulator) {
		Assert.notNull(authoritiesPopulator, "authoritiesPopulator cannot be null");
		this.authoritiesPopulator = authoritiesPopulator;
	}

	private boolean hasValidatorOfType(
			Collection<OAuth2TokenValidator<Jwt>> validators,
			Class<? extends OAuth2TokenValidator<Jwt>> target) {

		return validators.stream()
				.anyMatch(v -> target.isAssignableFrom(v.getClass()));
	}

	private static OAuth2Error invalidRequest(String message) {
		return new OAuth2Error(
				OAuth2ErrorCodes.INVALID_REQUEST,
				message,
				"https://tools.ietf.org/html/rfc6750#section-3.1"
		);
	}
}
