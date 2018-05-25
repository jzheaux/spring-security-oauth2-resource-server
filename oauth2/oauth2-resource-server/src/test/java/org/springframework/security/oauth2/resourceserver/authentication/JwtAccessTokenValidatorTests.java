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

import org.assertj.core.util.Maps;
import org.junit.Test;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Josh Cummings
 */
public class JwtAccessTokenValidatorTests {
	@Test
	public void validateWhenJwtIsExpiredThenErrorMessageIndicatesExpirationTime() {
		Instant expiry = Instant.MIN.plusSeconds(1);

		Jwt jwt = new Jwt(
				"token",
				Instant.MIN,
				expiry,
				Maps.newHashMap("alg", JwsAlgorithms.RS256),
				Maps.newHashMap(JwtClaimNames.EXP, expiry));

		JwtAccessTokenValidator validator = new JwtAccessTokenValidator();

		assertThat(validator.validate(jwt).getFailureReasons())
				.contains("Jwt expired at " + expiry);
	}

	@Test
	public void validateWhenJwtIsTooEarlyThenErrorMessageIndicatesNotBeforeTime() {
		Instant oneHourFromNow = Instant.now().plusSeconds(3600);

		Jwt jwt = new Jwt(
				"token",
				Instant.MIN,
				oneHourFromNow,
				Maps.newHashMap("alg", JwsAlgorithms.RS256),
				Maps.newHashMap(JwtClaimNames.NBF, oneHourFromNow));

		JwtAccessTokenValidator validator = new JwtAccessTokenValidator();

		assertThat(validator.validate(jwt).getFailureReasons())
				.contains("Jwt used before " + oneHourFromNow);
	}
}
