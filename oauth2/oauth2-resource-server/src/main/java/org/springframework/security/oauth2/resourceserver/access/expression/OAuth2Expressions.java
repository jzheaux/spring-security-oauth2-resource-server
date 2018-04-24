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

import java.util.Collection;

/**
 * A contract for the OAuth2 SpEL expressions entry point
 *
 * @author Josh Cummings
 * @since 5.1
 */
public interface OAuth2Expressions {

	/**
	 * Retreive an OAuth2 token attribute from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @param name
	 * @return
	 */
	Object attribute(Authentication authentication, String name);

	/**
	 * Retreive any OAuth2 scopes in the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return
	 */
	Collection<String> scopes(Authentication authentication);

	/**
	 * Confirm that the provided {@link Authentication} has the given scope
	 *
	 * @param authentication
	 * @param scope
	 * @return
	 */
	boolean hasScope(Authentication authentication, String scope);

	/**
	 * Confirm that the provided {@link Authentication} has any of the given scopes
	 *
	 * @param authentication
	 * @param scopes
	 * @return
	 */
	boolean hasAnyScope(Authentication authentication, String... scopes);

	/**
	 * Confirm that the provided {@link Authentication} has all of the given scopes
	 *
	 * @param authentication
	 * @param scopes
	 * @return
	 */
	boolean hasAllScopes(Authentication authentication, String... scopes);
}
