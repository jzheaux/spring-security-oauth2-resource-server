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

import java.util.Arrays;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.resourceserver.BearerTokenAuthenticationException;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;
import org.springframework.security.oauth2.resourceserver.BearerTokenErrorCodes;
import org.springframework.util.StringUtils;

/**
 * The default {@link BearerTokenResolver} implementation based on RFC 6750.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750 Section 2: Authenticated Requests</a>
 */
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

	static final String ERR_MSG_INVALID_TOKEN_IN_HEADER = "Invalid Bearer token in Authorization header";

	static final String ERR_MSG_MULTIPLE_TOKENS = "Clients MUST NOT use more than one method to transmit the token in each request";

	private static final String ACCESS_TOKEN_PARAM_NAME = "access_token";

	private static final BearerTokenError BEARER_TOKEN_ERROR = new BearerTokenError(
			BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST);

	private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+)=*$");

	private boolean allowFormEncodedBodyParameter = false;

	private boolean allowUriQueryParameter = false;

	@Override
	public String resolve(final HttpServletRequest request) {
		final String authorizationHeaderToken = resolveFromAuthorizationHeader(request);
		if ((authorizationHeaderToken != null && request.getParameter(ACCESS_TOKEN_PARAM_NAME) != null)||hasMultipleTokenParams(request)) {
			throw new BearerTokenAuthenticationException(BEARER_TOKEN_ERROR, ERR_MSG_MULTIPLE_TOKENS);
		} else {
			return authorizationHeaderToken != null ? authorizationHeaderToken : resolveFromRequestParameter(request);
		}
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported. Defaults to {@code false}.
	 * @param allowFormEncodedBodyParameter if the form-encoded body parameter is supported
	 */
	public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
		this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults to {@code false}.
	 *
	 * The spec recommends against using this mechanism for sending bearer tokens, and even goes as far as
	 * stating that it was only included for completeness.
	 *
	 * @param allowUriQueryParameter if the URI query parameter is supported
	 */
	public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
		this.allowUriQueryParameter = allowUriQueryParameter;
	}

	private static String resolveFromAuthorizationHeader(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		if (authorization != null && authorization.startsWith("Bearer")) {
			Matcher matcher = AUTHORIZATION_PATTERN.matcher(authorization);
			if (!matcher.matches()) {
				throw new BearerTokenAuthenticationException(BEARER_TOKEN_ERROR, ERR_MSG_INVALID_TOKEN_IN_HEADER);
			}

			return matcher.group("token");
		}
		return null;
	}

	private String resolveFromRequestParameter(HttpServletRequest request) {
		final boolean tokenInUriQueryParameter = isTokenInUriQueryParameter(request);
		if (this.allowFormEncodedBodyParameter && !tokenInUriQueryParameter
				&& "application/x-www-form-urlencoded".equalsIgnoreCase(request.getContentType())
				&& "POST".equalsIgnoreCase((request.getMethod()))) {
			return request.getParameter(ACCESS_TOKEN_PARAM_NAME);
		} else if (this.allowUriQueryParameter && tokenInUriQueryParameter) {
			return request.getParameter(ACCESS_TOKEN_PARAM_NAME);
		} else {
			return null;
		}
	}

	private boolean isTokenInUriQueryParameter(HttpServletRequest request) {
		final String queryString = request.getQueryString();
		return !StringUtils.isEmpty(queryString) && Arrays.stream(queryString.split("&"))
				.map(param -> param.split("=")[0]).map(paramName -> paramName.toLowerCase(Locale.ROOT))
				.anyMatch(Predicate.isEqual(ACCESS_TOKEN_PARAM_NAME));
	}

	private boolean hasMultipleTokenParams(HttpServletRequest request) {
		// Due to Servlet API limitations we cannot distinguish form vs query param here
		final String[] tokenValues = request.getParameterValues(ACCESS_TOKEN_PARAM_NAME);
		return tokenValues != null && tokenValues.length > 1;
	}

}
