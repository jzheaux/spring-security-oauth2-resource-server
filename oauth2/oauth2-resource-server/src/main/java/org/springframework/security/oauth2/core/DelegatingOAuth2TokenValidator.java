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

package org.springframework.security.oauth2.core;

import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

public class DelegatingOAuth2TokenValidator<T extends AbstractOAuth2Token> implements OAuth2TokenValidator<T> {
	private final Collection<OAuth2TokenValidator<T>> validators;

	public DelegatingOAuth2TokenValidator(OAuth2TokenValidator<T>... validators) {
		this(Arrays.asList(validators));
	}

	public DelegatingOAuth2TokenValidator(Collection<OAuth2TokenValidator<T>> validators) {
		Assert.notEmpty(validators, "validators must not be empty");

		this.validators = Collections.unmodifiableCollection(validators);
	}

	@Override
	public void validate(T token) throws OAuth2AuthenticationException {
		for ( OAuth2TokenValidator<T> validator : this.validators ) {
			validator.validate(token);
		}
	}

	public Collection<OAuth2TokenValidator<T>> getValidators() {
		return this.validators;
	}
}
