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
package org.springframework.security.oauth2.resourceserver;

import org.springframework.security.oauth2.core.OAuth2Error;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

/**
 * An error representing "insufficient_scope" from the OAuth Extensions Error Registry
 *
 * {@see }
 * @since 5.1
 * @author Josh Cummings
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-6.2.3" target="_blank">RFC 6750 Section 6.2.3: The "insufficient_scope" Error Value</a>
 */
public class InsufficientScopeError extends OAuth2Error {
	private Collection<String> scopes;

	public InsufficientScopeError(String... scopes) {
		this(Arrays.asList(scopes));
	}

	public InsufficientScopeError(Collection<String> scopes) {
		super("insufficient_scope", String.format("Resource requires any or all of these scopes %s", scopes), "https://tools.ietf.org/html/rfc6750#section-3.1");

		this.scopes = Collections.unmodifiableCollection(scopes);
	}

	public Collection<String> getScopes() {
		return this.scopes;
	}
}
