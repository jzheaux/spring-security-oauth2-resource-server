package org.springframework.security.oauth2.resource.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.resource.authentication.OAuth2ResourceAuthenticationFilter;
import org.springframework.security.oauth2.resource.authentication.OAuth2ResourceAuthenticationToken;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OAuthResourceAuthenticationFilterTest {
	@Mock
	AuthenticationManager authenticationManager;

	@Mock
	HttpServletRequest request;

	@Mock
	FilterChain filterChain;

	@InjectMocks
	OAuth2ResourceAuthenticationFilter filter;

	@Test
	public void whenBearerTokenPresent_thenAuthenticate() throws ServletException, IOException {
		String token = "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2UucmVhZCIsImlzcyI6InJvYiIsImV4cCI6MjE0NzQwNzIwMCwiaWF0IjoxNTE2MjU1MjAwfQ.dYAj3sOVUIfDl9TogBKbsenQ9jbu9QSZPEU1aeEtUTcdeNazDvrqhR8kMZHI0F4x8jGKmwB9CfnLsQti1obY0TedenYDm7_8WlX3EBWhUhNkwfnlFRWN_u-tOdWxZlm0UrAv55hGc8abkcp6BrPxAvGLGNBpwEPrvbOOfaiMZZA";

		when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

		filter.doFilterInternal(request, null, filterChain);

		ArgumentCaptor<OAuth2ResourceAuthenticationToken> captor = ArgumentCaptor.forClass(OAuth2ResourceAuthenticationToken.class);

		verify(authenticationManager).authenticate(captor.capture());

		assertEquals(token, captor.getValue().getPrincipal());
	}

	@Test
	public void whenNonBearerAuthorizationHeaderPresent_thenDontAuthenticate()
		throws ServletException, IOException {

		when(request.getHeader("Authorization")).thenReturn("Basic 1234");

		dontAuthenticate();
	}

	@Test
	public void whenNoAuthorizationHeaderPresent_thenDontAuthenticate()
		throws ServletException, IOException {

		when(request.getHeader("Authorization")).thenReturn(null);

		dontAuthenticate();
	}

	@Test
	public void whenMalformedAuthorizationHeader_thenDontAuthenticate()
		throws ServletException, IOException {

		when(request.getHeader("Authorization")).thenReturn("Bearer ");

		dontAuthenticate();
	}

	protected void dontAuthenticate()
		throws ServletException, IOException {

		filter.doFilterInternal(request, null, filterChain);

		verifyNoMoreInteractions(authenticationManager);
	}
}
