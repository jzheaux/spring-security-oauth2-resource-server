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

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.resourceserver.BearerTokenAuthenticationException;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;
import org.springframework.security.oauth2.resourceserver.BearerTokenErrorHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An {@link AuthenticationEntryPoint} implementation used to commence authentication of protected resource requests
 * using {@link BearerTokenAuthenticationFilter}.
 * <p>
 * Uses information provided by {@link BearerTokenError} to set HTTP response status code and populate
 * {@code WWW-Authenticate} HTTP header.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see BearerTokenAuthenticationException
 * @see BearerTokenError
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 * Response Header Field</a>
 */
public class BearerTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private BearerTokenErrorHandler handler = new BearerTokenErrorHandler();

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		if (authException instanceof BearerTokenAuthenticationException) {

			BearerTokenError error = ((BearerTokenAuthenticationException) authException).getError();

			this.handler.handle(
					request,
					response,
					error.getHttpStatus(), error.getErrorCode(),
					error.getDescription(), error.getUri(), error.getScope());
		} else if (authException instanceof OAuth2AuthenticationException) {

			OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();

			this.handler.handle(
					request,
					response,
					HttpStatus.UNAUTHORIZED, error.getErrorCode(),
					error.getDescription(), error.getUri(), null);
		} else {
			this.handler.handle(request, response, HttpStatus.UNAUTHORIZED);
		}
	}

	public void setBearerTokenErrorHandler(BearerTokenErrorHandler handler) {
		Assert.notNull(handler, "handler cannot be null");
		this.handler = handler;
	}

	/**
	 * Set the realm name.
	 * @param realmName the realm name
	 */
	public void setRealmName(String realmName) {
		this.handler.setRealmName(realmName);
	}
}
