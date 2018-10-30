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

import java.util.Base64;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.resourceserver.BearerTokenAuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DefaultBearerTokenResolver}.
 *
 * @author Vedran Pavic
 */
public class DefaultBearerTokenResolverTests {

	private static final String TEST_TOKEN = "test-token";

	private DefaultBearerTokenResolver resolver;

	@Before
	public void setUp() {
		this.resolver = new DefaultBearerTokenResolver();
	}

	@Test
	public void resolveWhenValidHeaderIsPresentThenTokenIsResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenNoHeaderIsPresentThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithWrongSchemeIsPresentThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("test:test".getBytes()));

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithInvalidCharactersIsPresentThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer an\"invalid\"token");

		assertThatThrownBy(() -> this.resolver.resolve(request)).isInstanceOf(BearerTokenAuthenticationException.class)
				.hasMessageContaining(DefaultBearerTokenResolver.ERR_MSG_INVALID_TOKEN_IN_HEADER);
	}

	@Test
	public void resolveWhenValidHeaderIsPresentTogetherWithFormParameterThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + TEST_TOKEN);
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThatThrownBy(() -> this.resolver.resolve(request)).isInstanceOf(BearerTokenAuthenticationException.class)
				.hasMessageContaining(DefaultBearerTokenResolver.ERR_MSG_MULTIPLE_TOKENS);
	}

	@Test
	public void resolveWhenValidHeaderIsPresentTogetherWithQueryParameterThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + TEST_TOKEN);
		request.setMethod("GET");
		request.setQueryString("access_token="+TEST_TOKEN);
		request.addParameter("access_token", TEST_TOKEN);

		assertThatThrownBy(() -> this.resolver.resolve(request)).isInstanceOf(BearerTokenAuthenticationException.class)
				.hasMessageContaining(DefaultBearerTokenResolver.ERR_MSG_MULTIPLE_TOKENS);
	}


	@Test
	public void resolveWhenMultipleParametersThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.setQueryString("access_token="+TEST_TOKEN);
		request.addParameter("access_token", TEST_TOKEN);
		request.addParameter("access_token", TEST_TOKEN);

		assertThatThrownBy(() -> this.resolver.resolve(request)).isInstanceOf(BearerTokenAuthenticationException.class)
				.hasMessageContaining(DefaultBearerTokenResolver.ERR_MSG_MULTIPLE_TOKENS);
	}

	@Test
	public void resolveWhenFormParameterIsPresentAndSupportedThenTokenIsResolved() {
		this.resolver.setAllowFormEncodedBodyParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenFormParameterIsPresentWithGetAndSupportedThenTokenIsNotResolved() {
		this.resolver.setAllowFormEncodedBodyParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenFormParameterIsPresentWithoutContentTypeAndSupportedThenTokenIsNotResolved() {
		this.resolver.setAllowFormEncodedBodyParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenFormParameterIsPresentAndNotSupportedThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndSupportedThenTokenIsResolved() {
		this.resolver.setAllowUriQueryParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		request.setQueryString("access_token="+TEST_TOKEN);
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenQueryParameterIsPresentWithPostAndSupportedThenTokenIsResolved() {
		this.resolver.setAllowUriQueryParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setQueryString("access_token="+TEST_TOKEN);
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndNotSupportedThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		request.setQueryString("access_token="+TEST_TOKEN);
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}


	@Test
	public void resolveWhenQueryParameterIsAbsentWithPostAndSupportedThenTokenIsNotResolved() {
		this.resolver.setAllowUriQueryParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}

}
