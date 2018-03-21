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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.resourceserver.authentication.OAuth2ResourceAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class BearerTokenAuthenticationFilterTests {
	@Mock
	AuthenticationEntryPoint authenticationEntryPoint;

	@Mock
	AuthenticationManager authenticationManager;

	@Mock
	HttpServletRequest request;

	@Mock
	FilterChain filterChain;

	@InjectMocks
	BearerTokenAuthenticationFilter filter;

	@Test
	public void whenBearerTokenPresent_thenAuthenticate() throws ServletException, IOException {
		String token = "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2UucmVhZCIsImlzcyI6InJvYiIsImV4cCI6MjE0NzQwNzIwMCwiaWF0IjoxNTE2MjU1MjAwfQ.dYAj3sOVUIfDl9TogBKbsenQ9jbu9QSZPEU1aeEtUTcdeNazDvrqhR8kMZHI0F4x8jGKmwB9CfnLsQti1obY0TedenYDm7_8WlX3EBWhUhNkwfnlFRWN_u-tOdWxZlm0UrAv55hGc8abkcp6BrPxAvGLGNBpwEPrvbOOfaiMZZA";

		when(this.request.getHeader("Authorization")).thenReturn("Bearer " + token);

		this.filter.doFilterInternal(this.request, null, this.filterChain);

		ArgumentCaptor<OAuth2ResourceAuthenticationToken> captor = ArgumentCaptor.forClass(OAuth2ResourceAuthenticationToken.class);

		verify(this.authenticationManager).authenticate(captor.capture());

		assertThat(captor.getValue().getPrincipal()).isEqualTo(token);
	}

	@Test
	public void whenNonBearerAuthorizationHeaderPresent_thenDontAuthenticate()
		throws ServletException, IOException {

		when(this.request.getHeader("Authorization")).thenReturn("Basic 1234");

		dontAuthenticate();
	}

	@Test
	public void whenNoAuthorizationHeaderPresent_thenDontAuthenticate()
		throws ServletException, IOException {

		when(this.request.getHeader("Authorization")).thenReturn(null);

		dontAuthenticate();
	}

	@Test
	public void whenMalformedAuthorizationHeader_thenDontAuthenticate()
		throws ServletException, IOException {

		when(this.request.getHeader("Authorization")).thenReturn("Bearer ");

		dontAuthenticate();
	}

	protected void dontAuthenticate()
		throws ServletException, IOException {

		this.filter.doFilterInternal(this.request, null, this.filterChain);

		verifyNoMoreInteractions(this.authenticationManager);
	}
}
