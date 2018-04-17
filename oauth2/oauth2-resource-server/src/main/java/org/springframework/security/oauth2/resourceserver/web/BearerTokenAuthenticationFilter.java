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

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationProvider;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An authentication filter that supports the OAuth2 Resource Server Bearer token flow. The intent is that the
 * {@link AuthenticationManager} would be wired with a {@link JwtAccessTokenAuthenticationProvider}
 * or some other {@link org.springframework.security.authentication.AuthenticationProvider} that supports
 * {@link PreAuthenticatedAuthenticationToken}.
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @author Joe Grandja
 * @since 5.1
 * @see JwtAccessTokenAuthenticationProvider
 */
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {
	private final AuthenticationManager authenticationManager;

	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
		new WebAuthenticationDetailsSource();

	private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

	private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();

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

		String token = this.bearerTokenResolver.resolve(request);

		if (token == null) {
			filterChain.doFilter(request, response);
			return;
		}

		PreAuthenticatedAuthenticationToken authenticationRequest = new PreAuthenticatedAuthenticationToken(token, null);

		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		try {
			Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);

			SecurityContextHolder.getContext().setAuthentication(authenticationResult);

			filterChain.doFilter(request, response);

			// this is currently a point of debate as to which kind of exception should be caught/thrown in this flow
			// {@see JwtVerificationException} for details.
		} catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();

			if (debug) {
				this.logger.debug("Authentication request for failed: " + failed);
			}

			this.authenticationEntryPoint.commence(request, response, failed);
		}
	}

	/**
	 * Set the {@link BearerTokenResolver} to use. Defaults to {@link DefaultBearerTokenResolver}.
	 * @param bearerTokenResolver the {@code BearerTokenResolver} to use
	 */
	public void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver must not be null");
		this.bearerTokenResolver = bearerTokenResolver;
	}

	/**
	 * Set the {@link AuthenticationEntryPoint} to use. Defaults to {@link BearerTokenAuthenticationEntryPoint}.
	 * @param authenticationEntryPoint the {@code AuthenticationEntryPoint} to use
	 */
	public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint must not be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

}
