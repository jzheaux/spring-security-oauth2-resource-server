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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.resourceserver.BearerTokenAuthenticationException;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

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

	private String realmName;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		HttpStatus httpStatus;
		Map<String, String> authParamAttributes = new LinkedHashMap<>();
		if (this.realmName != null) {
			authParamAttributes.put("realm", this.realmName);
		}
		if (authException instanceof BearerTokenAuthenticationException) {
			BearerTokenError error = ((BearerTokenAuthenticationException) authException).getError();
			httpStatus = error.getHttpStatus();
			authParamAttributes.put("error", error.getErrorCode());
			String description = error.getDescription();
			if (description != null) {
				authParamAttributes.put("error_description", description);
			}
			String uri = error.getUri();
			if (uri != null) {
				authParamAttributes.put("error_uri", uri);
			}
			String scope = error.getScope();
			if (scope != null) {
				authParamAttributes.put("scope", scope);
			}
		}
		else {
			httpStatus = HttpStatus.UNAUTHORIZED;
		}
		String wwwAuthenticate = "Bearer";
		if (!authParamAttributes.isEmpty()) {
			wwwAuthenticate += authParamAttributes.entrySet().stream()
					.map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
					.collect(Collectors.joining(", ", " ", ""));
		}
		response.addHeader("WWW-Authenticate", wwwAuthenticate);
		response.sendError(httpStatus.value(), httpStatus.getReasonPhrase());
	}

	/**
	 * Set the realm name.
	 * @param realmName the realm name
	 */
	public void setRealmName(String realmName) {
		Assert.hasText(realmName, "realmName must not be null");
		this.realmName = realmName;
	}

}
