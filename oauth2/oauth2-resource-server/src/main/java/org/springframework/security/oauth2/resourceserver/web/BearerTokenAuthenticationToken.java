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

package org.springframework.security.oauth2.resourceserver.web;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken  {
	private String token;

	public BearerTokenAuthenticationToken(String token) {
		super(Collections.emptyList());
		this.token = token;
	}

	public String getToken() {
		return this.token;
	}

	@Override
	public Object getCredentials() {
		return this.token;
	}

	@Override
	public Object getPrincipal() {
		return this.token;
	}
}
