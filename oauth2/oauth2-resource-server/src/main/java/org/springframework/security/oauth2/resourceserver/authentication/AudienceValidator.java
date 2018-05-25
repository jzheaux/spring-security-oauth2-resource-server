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
import java.util.Collections;

public class AudienceValidator implements JwtTokenValidator {
	private Collection<String> permitted;

	private OAuth2TokenValidationResult failure;

	public AudienceValidator(String... permitted) {
		this(Arrays.asList(permitted));
	}

	public AudienceValidator(Collection<String> permitted) {
		Assert.notEmpty(permitted, "permitted must not be empty");
		this.permitted = Collections.unmodifiableCollection(permitted);
		this.failure = OAuth2TokenValidationResult.error("Attribute [aud] must be in %s", this.permitted);
	}

	@Override
	public OAuth2TokenValidationResult validate(Jwt token) {
		if ( !containsAny(token.getAudience()) ) {
			return this.failure;
		}

		return OAuth2TokenValidationResult.SUCCESS;
	}

	private boolean containsAny(Collection<String> audiences) {
		return audiences.stream().anyMatch(this.permitted::contains);
	}
}
