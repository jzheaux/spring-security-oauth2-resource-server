package org.springframework.security.oauth2.auth0;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

import static org.junit.Assert.*;

public class PemParsingPublicKeyOnlyRSAKeyProviderTest {
	@Test
	public void whenPemEncoded_thenCanParse() throws IOException {
		InputStream is = this.getClass()
			.getClassLoader().getResourceAsStream("id_rsa.pub");

		PemParsingPublicKeyOnlyRSAKeyProvider provider =
			new PemParsingPublicKeyOnlyRSAKeyProvider(is);

		RSAPublicKey key = provider.getPublicKeyById("123");

		assertEquals(new BigInteger("65537"), key.getPublicExponent());
	}
}
