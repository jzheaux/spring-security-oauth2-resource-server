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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidationResult;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationToken;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
	OAuth2TokenValidator<Jwt> validator;

	@Mock
	Jwt jwt;

	JwtAccessTokenAuthenticationProvider provider;

	@Before
	public void setup() {
		this.provider =
				new JwtAccessTokenAuthenticationProvider(
						this.jwtDecoder,
						Arrays.asList(this.validator)
				);
	}

	@Test
	public void authenticateWhenJwtDecodesThenAuthenticationHasAttributesContainedInJwt() {
		BearerTokenAuthenticationToken token = this.authentication();
		Map<String, Object> claims = new HashMap<>();
		claims.put("name", "value");

		when(this.jwtDecoder.decode("token")).thenReturn(this.jwt);
		when(this.jwt.getClaims()).thenReturn(claims);
		when(this.validator.validate(this.jwt)).thenReturn(OAuth2TokenValidationResult.SUCCESS);

		JwtAccessTokenAuthenticationToken jwtAccessTokenAuthentication =
				(JwtAccessTokenAuthenticationToken) this.provider.authenticate(token);

		assertThat(jwtAccessTokenAuthentication.hasAttribute("name", "value")).isTrue();
	}

	@Test
	public void authenticateWhenJwtDecodeFailsThenRespondsWithInvalidRequest() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenThrow(JwtException.class);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(OAuth2ErrorCodes.INVALID_REQUEST));
	}

	@Test
	public void authenticateWhenJwtValidatorFailsThenResponseWithInvalidRequest() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenReturn(this.jwt);
		when(this.validator.validate(this.jwt)).thenReturn(OAuth2TokenValidationResult.error("reason"));

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	private BearerTokenAuthenticationToken authentication() {
		return new BearerTokenAuthenticationToken("token");
	}

	private Predicate<? super Throwable> errorCode(String errorCode) {
		return failed ->
				((OAuth2AuthenticationException) failed).getError().getErrorCode() == errorCode;
	}
}
