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

import java.net.URL;
import java.time.Instant;
import java.util.Collection;

/**
 * A contract for the JWT SpEL expressions entry point
 *
 * @author Josh Cummings
 * @since 5.1
 */
public interface JwtExpressions {

	/**
	 * Retreive the JWT audience list from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	Collection<String> audience(Authentication authentication);

	/**
	 * Retreive the JWT expiration time from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	Instant expiresAt(Authentication authentication);

	/**
	 * Retreive the JWT id from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	String id(Authentication authentication);

	/**
	 * Retreive the JWT issue time from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	Instant issuedAt(Authentication authentication);

	/**
	 * Retreive the JWT issuer from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	URL issuer(Authentication authentication);

	/**
	 * Retreive the JWT not before from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	Instant notBefore(Authentication authentication);

	/**
	 * Retreive the JWT subject from the provided {@link Authentication}
	 *
	 * @param authentication
	 * @return the list of audiences, if any; null if none
	 */
	String subject(Authentication authentication);
}
