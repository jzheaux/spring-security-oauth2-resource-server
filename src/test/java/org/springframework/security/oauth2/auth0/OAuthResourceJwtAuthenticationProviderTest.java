package org.springframework.security.oauth2.auth0;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.resource.authentication.OAuth2ResourceAuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OAuthResourceJwtAuthenticationProviderTest {
	@Mock
	JwtVerifier jwtVerifier;

	@Mock
	DecodedJWT decodedJwt;

	@Mock
	Claim scope;

	@InjectMocks
	OAuthResourceJwtAuthenticationProvider provider;

	@Test
	public void whenSuccessfulDecode_thenMarkAuthenticated() {
		String token = "good token";
		List<String> scopes = Arrays.asList("message.read", "message.write");

		when(jwtVerifier.verify(token)).thenReturn(decodedJwt);
		when(decodedJwt.getClaim("scope")).thenReturn(scope);
		when(scope.asString()).thenReturn(String.join(" ", scopes));

		Authentication a = provider.authenticate(new OAuth2ResourceAuthenticationToken(token));

		Collection<String> authorities = a.getAuthorities()
			.stream()
			.map(ga -> ga.getAuthority())
			.collect(Collectors.toList());

		assertEquals(scopes, authorities);
		assertTrue(a.isAuthenticated());
	}

	@Test(expected = CredentialsExpiredException.class)
	public void whenExpiredToken_thenThrowCredentialsExpiredException() {
		when(jwtVerifier.verify(any(String.class))).thenThrow(new TokenExpiredException("token expired"));

		provider.authenticate(new OAuth2ResourceAuthenticationToken("deadbeef"));
	}

	@Test(expected = BadCredentialsException.class)
	public void whenMalformedToken_thenThrowBadCredentialsException() {
		when(jwtVerifier.verify(any(String.class))).thenThrow(new JWTVerificationException("token is bad"));

		provider.authenticate(new OAuth2ResourceAuthenticationToken("deadbeef"));
	}
}
