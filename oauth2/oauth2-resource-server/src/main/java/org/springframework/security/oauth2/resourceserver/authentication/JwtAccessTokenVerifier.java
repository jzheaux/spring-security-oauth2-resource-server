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

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * An implementation of {@see JwtVerifier} for verifying claims in a Jwt-based access token
 *
 * <p>
 * Because clocks can differ between the Jwt source, say the Authorization Server, and its destination, say the
 * Resource Server, there is a default clock leeway exercised when deciding if the current time is within the Jwt's
 * specified operating window
 *
 * <p>
 * Custom verification can be appended to instances of this class by providing a custom implementation of
 * {@see JwtVerifier}
 *
 * @author Josh Cummings
 * @since 5.1
 * @see Jwt
 * @see OAuth2TokenVerifier
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 */
public class JwtAccessTokenVerifier implements OAuth2TokenVerifier<Jwt> {
	private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);

	private final OAuth2TokenVerifier<Jwt> additionalVerification;

	private final Duration maxClockSkew;

	/**
	 * A basic instance with no custom verification and the default max clock skew
	 */
	public JwtAccessTokenVerifier() {
		this((jwt) -> {});
	}

	public JwtAccessTokenVerifier(OAuth2TokenVerifier<Jwt> jwtVerifier) {
		this(jwtVerifier, DEFAULT_MAX_CLOCK_SKEW);
	}

	public JwtAccessTokenVerifier(OAuth2TokenVerifier<Jwt> jwtVerifier, Duration maxClockSkew) {
		Assert.notNull(jwtVerifier, "jwtVerifier cannot be null");
		Assert.notNull(maxClockSkew, "maxClockSkew cannot be null");

		this.additionalVerification = jwtVerifier;
		this.maxClockSkew = maxClockSkew;
	}

	@Override
	public void verify(Jwt jwt) throws OAuth2AuthenticationException {
		Instant expiry = jwt.getExpiresAt();

		if ( expiry != null && expiry.isBefore(Instant.MAX) ) {
			if ( Instant.now().isAfter(expiry.plus(maxClockSkew)) ) {
				OAuth2Error invalidRequest = new OAuth2Error(
						OAuth2ErrorCodes.INVALID_REQUEST,
						String.format("Jwt expired at %s", jwt.getExpiresAt()),
						null);
				throw new OAuth2AuthenticationException(invalidRequest, invalidRequest.toString());
			}
		}

		Instant notBefore = jwt.getNotBefore();

		if ( notBefore != null && notBefore.isAfter(Instant.MIN) ) {
			if ( Instant.now().isBefore(notBefore.minus(maxClockSkew)) ) {
				OAuth2Error invalidRequest = new OAuth2Error(
						OAuth2ErrorCodes.INVALID_REQUEST,
						String.format("Jwt used before %s", jwt.getNotBefore()),
						null);
				throw new OAuth2AuthenticationException(invalidRequest, invalidRequest.toString());
			}
		}

		additionalVerification.verify(jwt);
	}
}
