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


import org.springframework.security.access.AccessDeniedException;

/**
 * An {@link AccessDeniedException} for OAuth2 access denial scenarios
 */
public class OAuth2AccessDeniedException extends AccessDeniedException {
	private final OAuth2Error error;

	public OAuth2AccessDeniedException(OAuth2Error error) {
		super(error.getDescription());

		this.error = error;
	}

	public OAuth2Error getError() {
		return this.error;
	}
}
