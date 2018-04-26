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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A class for formulating and sending OAuth2 Bearer Token error responses
 *
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 */
public class BearerTokenErrorHandler {
	private String realmName;

	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			HttpStatus httpStatus) throws IOException {

		this.handle(response, authParamAttributes(), httpStatus);
	}

	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			HttpStatus httpStatus, String error, String description, String uri, String scope) throws IOException {

		Map<String, String> authParamAttributes = authParamAttributes();

		authParamAttributes.put("error", error);

		if (description != null) {
			authParamAttributes.put("error_description", description);
		}

		if (uri != null) {
			authParamAttributes.put("error_uri", uri);
		}

		if (scope != null) {
			authParamAttributes.put("scope", scope);
		}

		this.handle(response, authParamAttributes, httpStatus);
	}

	protected Map<String, String> authParamAttributes() {
		Map<String, String> authParamAttributes = new LinkedHashMap<>();

		if ( this.realmName != null ) {
			authParamAttributes.put("realm", this.realmName);
		}

		return authParamAttributes;
	}

	protected void handle(
			HttpServletResponse response,
			Map<String, String> authParamAttributes,
			HttpStatus httpStatus) throws IOException {

		String wwwAuthenticate = "Bearer";
		if (!authParamAttributes.isEmpty()) {
			wwwAuthenticate += authParamAttributes.entrySet().stream()
					.map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
					.collect(Collectors.joining(", ", " ", ""));
		}
		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		response.setStatus(httpStatus.value());
	}

	public void setRealmName(String realmName) {
		this.realmName = realmName;
	}
}
