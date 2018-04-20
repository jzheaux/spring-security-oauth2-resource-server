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
package org.springframework.security.oauth2.resourceserver.access.expression;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.resourceserver.authentication.AbstractOAuth2AccessTokenAuthenticationToken;

import java.util.Collections;
import java.util.Optional;

/**
 * A class for evaluating SpEL expressions based on OAuth2 Authentication tokens.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see AbstractOAuth2AccessTokenAuthenticationToken
 */
public class DefaultOAuth2Expressions implements OAuth2Expressions {

	private ClaimAccessor authority(Authentication authentication) {
		return () -> Optional.ofNullable(authentication)
				.filter(auth -> auth instanceof AbstractOAuth2AccessTokenAuthenticationToken)
				.map(auth -> (AbstractOAuth2AccessTokenAuthenticationToken) auth)
				.map(auth -> auth.getTokenAttributes())
				.orElse(Collections.emptyMap());
	}

	@Override
	public Object attribute(Authentication authentication, String name) {
		return authority(authentication).getClaims().get(name);
	}
}
