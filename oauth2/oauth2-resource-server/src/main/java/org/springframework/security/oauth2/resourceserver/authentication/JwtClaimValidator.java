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
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

public class JwtClaimValidator implements JwtTokenValidator {
	private final String name;
	private final Collection<String> values;

	public JwtClaimValidator(String name, String... value) {
		this.name = name;
		this.values = Arrays.asList(value);
	}

	@Override
	public void validate(Jwt token) throws OAuth2AuthenticationException {
		Optional.ofNullable(token.getClaims().get(name))
				.map(String::valueOf)
				.filter(this.values::contains)
				.orElseThrow(() -> {
					OAuth2Error error = new OAuth2Error(
							OAuth2ErrorCodes.INVALID_REQUEST,
							String.format("Attribute [%s] must be in %s", this.name, this.values),
							null);

					return new OAuth2AuthenticationException(error, error.toString());
				});
	}
}
