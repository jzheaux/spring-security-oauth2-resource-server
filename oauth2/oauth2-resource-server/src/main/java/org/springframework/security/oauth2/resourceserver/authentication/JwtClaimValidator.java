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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

public class JwtClaimValidator implements JwtTokenValidator {
	private final String name;
	private final Collection<String> values;

	private final OAuth2TokenValidationResult failure;

	public JwtClaimValidator(String name, String... values) {
		Assert.notNull(name, "name must not be null");

		this.name = name;
		this.values = Arrays.asList(values);
		this.failure = OAuth2TokenValidationResult.error("Attribute [%s] must be in %s", this.name, this.values);
	}

	@Override
	public OAuth2TokenValidationResult validate(Jwt token) {
		return Optional
				.ofNullable(token.getClaims().get(this.name))
				.map(String::valueOf)
				.filter(this.values::contains)
				.map(value -> OAuth2TokenValidationResult.SUCCESS)
				.orElse(this.failure);
	}
}
