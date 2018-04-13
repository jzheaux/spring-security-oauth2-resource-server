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
package org.springframework.security.oauth2.resourceserver.authentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.AccessTokenJwtVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JwtAccessTokenAuthenticationProvider}
 *
 * @author Josh Cummings
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtAccessTokenAuthenticationProviderTests {
	@Mock
	JwtDecoder jwtDecoder;

	@Mock
	AccessTokenJwtVerifier jwtVerifier;

	@Mock
	Jwt jwt;

	@InjectMocks
	JwtAccessTokenAuthenticationProvider provider;

	@Test
	public void authenticateWhenJwtDecodesThenAuthenticationHasAttributesContainedInJwt() {
		PreAuthenticatedAuthenticationToken token = this.authentication();
		Map<String, Object> claims = new HashMap<>();
		claims.put("name", "value");

		when(this.jwtDecoder.decode("token")).thenReturn(this.jwt);
		when(this.jwt.getClaims()).thenReturn(claims);

		JwtAccessTokenAuthenticationToken jwtAccessTokenAuthentication =
				(JwtAccessTokenAuthenticationToken) this.provider.authenticate(token);

		assertThat(jwtAccessTokenAuthentication.hasAttribute("name", "value")).isTrue();
	}

	@Test
	public void authenticateWhenJwtDecodeFailsThenRespondsWithInvalidRequest() {
		PreAuthenticatedAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenThrow(JwtException.class);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(OAuth2ErrorCodes.INVALID_REQUEST));
	}

	@Test
	public void authenticateWhenJwtVerifierFailsThenResponseWithInvalidRequest() {
		PreAuthenticatedAuthenticationToken token = this.authentication();

		doThrow(JwtException.class).when(this.jwtVerifier).verifyClaims(null);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(OAuth2ErrorCodes.INVALID_REQUEST));
	}

	private PreAuthenticatedAuthenticationToken authentication() {
		return new PreAuthenticatedAuthenticationToken("token", null);
	}

	private Predicate<? super Throwable> errorCode(String errorCode) {
		return failed ->
				((OAuth2AuthenticationException) failed).getError().getErrorCode() == errorCode;
	}
}
