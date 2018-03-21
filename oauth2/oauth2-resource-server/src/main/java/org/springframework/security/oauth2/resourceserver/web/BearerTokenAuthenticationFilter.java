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
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.resourceserver.authentication.OAuth2ResourceAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * An authentication filter that supports the OAuth2 Resource Server Bearer token flow. The intent is that the
 * {@link AuthenticationManager} would be wired with a {@link JwtEncodedOAuth2AccessTokenAuthenticationProvider}
 * or some other {@link org.springframework.security.authentication.AuthenticationProvider} that supports
 * {@link OAuth2ResourceAuthenticationToken}s.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see JwtEncodedOAuth2AccessTokenAuthenticationProvider
 * @see OAuth2ResourceAuthenticationToken
 */
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {
	private final AuthenticationManager authenticationManager;

	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
		new WebAuthenticationDetailsSource();

	private AuthenticationEntryPoint authenticationEntryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

	public BearerTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager is required");
		this.authenticationManager = authenticationManager;
	}

	public BearerTokenAuthenticationFilter(AuthenticationManager authenticationManager,
										   AuthenticationEntryPoint authenticationEntryPoint) {
		this(authenticationManager);

		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint is required");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {

		final boolean debug = this.logger.isDebugEnabled();

		String token = this.bearerToken(request);

		if (token == null) {
			filterChain.doFilter(request, response);
			return;
		}

		OAuth2ResourceAuthenticationToken authenticationRequest =
			new OAuth2ResourceAuthenticationToken(token);

		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		try {
			OAuth2ResourceAuthenticationToken authenticationResult =
				(OAuth2ResourceAuthenticationToken)
					this.authenticationManager.authenticate(new OAuth2ResourceAuthenticationToken(token));

			SecurityContextHolder.getContext().setAuthentication(authenticationResult);

			onSuccessfulAuthentication(request, response, authenticationResult);

			filterChain.doFilter(request, response);

			// this is currently a point of debate as to which kind of exception should be caught/thrown in this flow
			// {@see JwtVerificationException} for details.
		} catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();

			if (debug) {
				this.logger.debug("Authentication request for failed: " + failed);
			}

			onUnsuccessfulAuthentication(request, response, failed);

			this.authenticationEntryPoint.commence(request, response, failed);
		}
	}

	/**
	 * Retrieve the any bearer token from the request
	 *
	 * @param req
	 * @return
	 */
	protected String bearerToken(HttpServletRequest req) {
		return Optional.ofNullable(req.getHeader("Authorization"))
			.filter(header -> header.startsWith("Bearer ") && header.length() > 7)
			.map(header -> header.substring(7))
			.orElse(null);
	}

	/**
	 * A hook for engineers to be alerted of bearer token verification success. Uses might be auditing or monitoring related.
	 *
	 * @param request
	 * @param response
	 * @param authResult
	 * @throws IOException
	 */
	protected void onSuccessfulAuthentication(HttpServletRequest request,
											  HttpServletResponse response,
											  Authentication authResult) throws IOException {
	}

	/**
	 * A hook for engineers to be alerted of bearer token verification failure. Uses might be auditing or monitoring related.
	 *
	 * @param request
	 * @param response
	 * @param failed
	 * @throws IOException
	 */
	protected void onUnsuccessfulAuthentication(HttpServletRequest request,
												HttpServletResponse response,
												AuthenticationException failed) throws IOException {
	}
}
