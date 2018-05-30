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

import org.springframework.security.oauth2.core.OAuth2TokenValidationResult;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * An implementation of {@see OAuth2TokenValidator} for verifying claims in a Jwt-based access token
 *
 * <p>
 * Because clocks can differ between the Jwt source, say the Authorization Server, and its destination, say the
 * Resource Server, there is a default clock leeway exercised when deciding if the current time is within the Jwt's
 * specified operating window
 *
 * @author Josh Cummings
 * @since 5.1
 * @see Jwt
 * @see OAuth2TokenValidator
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 */
public class JwtTimestampsValidator implements JwtTokenValidator {
	private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);

	private final Duration maxClockSkew;

	private Clock clock = Clock.systemUTC();

	/**
	 * A basic instance with no custom verification and the default max clock skew
	 */
	public JwtTimestampsValidator() {
		this(DEFAULT_MAX_CLOCK_SKEW);
	}

	public JwtTimestampsValidator(Duration maxClockSkew) {
		Assert.notNull(maxClockSkew, "maxClockSkew cannot be null");

		this.maxClockSkew = maxClockSkew;
	}

	@Override
	public OAuth2TokenValidationResult validate(Jwt jwt) {
		OAuth2TokenValidationResult.Builder result =
				new OAuth2TokenValidationResult.Builder();

		Instant expiry = jwt.getExpiresAt();

		if ( expiry != null ) {
			if ( Instant.now(this.clock).minus(maxClockSkew).isAfter(expiry) ) {
				result.error("Jwt expired at %s", jwt.getExpiresAt());
			}
		}

		Instant notBefore = jwt.getNotBefore();

		if ( notBefore != null ) {
			if ( Instant.now(this.clock).plus(maxClockSkew).isBefore(notBefore) ) {
				result.error("Jwt used before %s", jwt.getNotBefore());
			}
		}

		return result.build();
	}

	/**
	 * Specify the {@link Clock} used by {@link Instant} for assessing
	 * timestamp validity
	 *
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}
}
