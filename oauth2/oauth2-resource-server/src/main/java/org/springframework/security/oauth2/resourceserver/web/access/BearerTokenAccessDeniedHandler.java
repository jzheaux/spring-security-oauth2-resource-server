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
package org.springframework.security.oauth2.resourceserver.web.access;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;
import org.springframework.security.oauth2.resourceserver.BearerTokenErrorHandler;
import org.springframework.security.oauth2.resourceserver.InsufficientScopeError;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;

public class BearerTokenAccessDeniedHandler implements AccessDeniedHandler {
	private BearerTokenErrorHandler handler = new BearerTokenErrorHandler();

	@Override
	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			AccessDeniedException accessDeniedException)
			throws IOException, ServletException {

		if ( accessDeniedException instanceof OAuth2AccessDeniedException ) {
			OAuth2Error error = ((OAuth2AccessDeniedException) accessDeniedException).getError();

			if ( error instanceof BearerTokenError ) {
				this.handle(request, response, (BearerTokenError) error);
			} else if ( error instanceof InsufficientScopeError ) {
				this.handle(request, response, (InsufficientScopeError) error);
			} else {
				this.handle(request, response, error);
			}
		} else {
			this.handler.handle(request, response, HttpStatus.FORBIDDEN);
		}
	}

	private void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			OAuth2Error error) throws IOException {

		this.handler.handle(request, response,
				HttpStatus.FORBIDDEN,
				error.getErrorCode(),
				error.getDescription(),
				error.getUri(),
				null);
	}

	private void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			BearerTokenError error) throws IOException {

		this.handler.handle(request, response,
				error.getHttpStatus(),
				error.getErrorCode(),
				error.getDescription(),
				error.getUri(),
				error.getScope());
	}

	private void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			InsufficientScopeError error) throws IOException {

		this.handler.handle(request, response,
				HttpStatus.FORBIDDEN,
				error.getErrorCode(),
				error.getDescription(),
				error.getUri(),
				error.getScopes().stream().collect(Collectors.joining(" ")));
	}

	public void setBearerTokenErrorHandler(BearerTokenErrorHandler handler) {
		this.handler = handler;
	}
}
