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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.bearer.OAuth2AccessTokenAuthority;
import org.springframework.security.oauth2.jwt.AccessTokenJwtVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JwtEncodedOAuth2AccessTokenAuthenticationProvider}
 *
 * @author Josh Cummings
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtEncodedOAuth2AccessTokenAuthenticationProviderTests {
	@Mock
	JwtDecoder jwtDecoder;

	@Mock
	AccessTokenJwtVerifier jwtVerifier;

	@Mock
	Jwt jwt;

	@InjectMocks
	JwtEncodedOAuth2AccessTokenAuthenticationProvider provider;

	@Test
	public void authenticateWhenJwtDecodesThenAuthenticationHasAttributesContainedInJwt() {
		OAuth2ResourceAuthenticationToken token = this.authentication();
		Map<String, Object> claims = new HashMap<>();
		claims.put("name", "value");

		when(this.jwtDecoder.decode("token")).thenReturn(this.jwt);
		when(this.jwt.getClaims()).thenReturn(claims);

		token = (OAuth2ResourceAuthenticationToken) this.provider.authenticate(token);

		assertThat(token.getAuthorities().iterator().next()).isInstanceOf(OAuth2AccessTokenAuthority.class);
		assertThat(token.hasClaim("name", "value")).isTrue();
	}

	@Test
	public void authenticateWhenJwtDecodeFailsThenRespondsWithInvalidRequest() {
		OAuth2ResourceAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenThrow(JwtException.class);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(OAuth2ErrorCodes.INVALID_REQUEST));
	}

	@Test
	public void authenticateWhenJwtVerifierFailsThenResponseWithInvalidRequest() {
		OAuth2ResourceAuthenticationToken token = this.authentication();

		doThrow(JwtException.class).when(this.jwtVerifier).verifyClaims(null);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(OAuth2ErrorCodes.INVALID_REQUEST));
	}

	@Test
	public void authenticateWhenAuthoritiesMappedThenAuthenticationHasMappedAuthorities() {
		GrantedAuthoritiesMapper mapper = (authorities) -> {
			SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
			List<GrantedAuthority> composite = new ArrayList<>(authorities);
			composite.add(0, authority);
			return composite;
		};

		this.provider.setAuthoritiesMapper(mapper);

		OAuth2ResourceAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenReturn(this.jwt);
		when(this.jwt.getClaims()).thenReturn(new HashMap<>());

		token = (OAuth2ResourceAuthenticationToken) this.provider.authenticate(token);

		assertThat(token.getAuthorities().iterator().next()).isInstanceOf(SimpleGrantedAuthority.class);
	}

	@Test
	public void authenticateWhenTokenNotSupportedThenAbstains() {
		UsernamePasswordAuthenticationToken unsupported =
				new UsernamePasswordAuthenticationToken("principal", "credentials");

		assertThat(this.provider.authenticate(unsupported)).isNull();
	}

	private OAuth2ResourceAuthenticationToken authentication() {
		return new OAuth2ResourceAuthenticationToken("token");
	}

	private Predicate<? super Throwable> errorCode(String errorCode) {
		return failed ->
				((OAuth2AuthenticationException) failed).getError().getErrorCode() == errorCode;
	}
}
