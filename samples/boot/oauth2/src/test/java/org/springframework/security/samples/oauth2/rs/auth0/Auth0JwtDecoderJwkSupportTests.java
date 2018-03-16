package org.springframework.security.samples.oauth2.rs.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtVerificationException;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class Auth0JwtDecoderJwkSupportTests {
	@Test
	public void whenSignatureAndIssuerValid_thenDecodeToken() throws IOException {
		String goodToken = "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2UucmVhZCIsImlzcyI6InJvYiIsImV4cCI6MjE0NzQwNzIwMCwiaWF0IjoxNTE2MjU1MjAwfQ.XJ8d6fQpo53eH_8nduS7rZOB9szHkVTYkZgzfpF3s6dq0DH-ovgFWBE1evfIXHTQwpAil1X856lp_mvJH0pWVXjM2jM5g_qMGen25210-9R9A94ShiM3iSeMAozHl2L6nmdifJR9Na0fWPo4rogB6_N0GoBG2haaB9yU2r925hw";

		Jwt jwt = defaultVerifier().decode(goodToken);
		assertEquals("rob", jwt.getClaims().get("iss"));
	}

	@Test(expected = JwtVerificationException.class)
	public void whenIssuerInvalid_thenInvalidClaimException() throws IOException {
		String badIssuer = "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2Uud3JpdGUiLCJpc3MiOiJyb2JiaWUiLCJleHAiOjIxNDc0MDcyMDAsImlhdCI6MTUxNjI1NTIwMH0.HS5K1QVcJoFmWc6VWJA9VQOYoKv_I0d8VQseeOAik1ZZ5GgQmEZLLuLJgUKvEx4Kodq9ZUyvApuQx0lvl1HqJEEBW80i7_-6ZPSiy9O4VLrXg4nBIxWqYwZ8ASza_7EsUvdo5FUtyyNRFL32jWnXhf5JMN2zxVQcuA4wBiX5VHM";

		defaultVerifier().decode(badIssuer);
	}

	@Test(expected = JwtVerificationException.class)
	public void whenAlgInvalid_thenAlgorithmMismatchException() throws IOException {
		String badAlg = "eyJraWQiOiIxMjM0IiwidHlwIjoiSldUIiwiYWxnIjoibm9uZSJ9.eyJzY29wZSI6Im1lc3NhZ2Uud3JpdGUgbWVzc2FnZS5yZWFkIiwiaXNzIjoicm9iIiwiZXhwIjoyMTQ3NDA3MjAwLCJpYXQiOjE1MTYyNTUyMDB9.0";

		defaultVerifier().decode(badAlg);
	}

	@Test(expected = JwtVerificationException.class)
	public void whenExpired_thenTokenExpiredException() throws IOException {
		String expired = "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2Uud3JpdGUgbWVzc2FnZS5yZWFkIiwiaXNzIjoicm9iIiwiZXhwIjoxNTE2MjU1MjAwLCJpYXQiOjE1MTYyNTUyMDB9.E6I2qUsoyvT5EXXVia7280nFgUg3qFJKVQhSajQYE3elbMFInS_BwqclrCxA55tyNgTZ-8FaUArnGI3mccPRd5ugSi0eG9_sFq3_Us0hi1Wfk6k8BlJd-UXnuJ6w9cd7VoX7jonuxG35nCh9Nh8iPrSDw7jpd2SDtN6D6Q6Ft4A";

		defaultVerifier().decode(expired);
	}

	protected Auth0JwtDecoderJwkSupport defaultVerifier() throws IOException {
		InputStream is = this.getClass()
			.getClassLoader().getResourceAsStream("id_rsa.pub");

		RSAKeyProvider key =
			new PemParsingPublicKeyOnlyRSAKeyProvider(is);

		JWTVerifier verifier = JWT.require(Algorithm.RSA256(key)).withIssuer("rob").build();

		return new Auth0JwtDecoderJwkSupport(verifier);
	}
}
