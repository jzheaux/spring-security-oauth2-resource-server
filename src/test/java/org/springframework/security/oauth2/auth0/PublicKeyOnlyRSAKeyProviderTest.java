package org.springframework.security.oauth2.auth0;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.interfaces.RSAPublicKey;

@RunWith(MockitoJUnitRunner.class)
public class PublicKeyOnlyRSAKeyProviderTest {
	PublicKeyOnlyRSAKeyProvider provider = new PublicKeyOnlyRSAKeyProvider() {
		@Override
		public RSAPublicKey getPublicKeyById(String s) {
			return null;
		}
	};

	@Test(expected = UnsupportedOperationException.class)
	public void whenTryPrivateKey_thenError() {
		provider.getPrivateKey();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void whenTryPrivateKeyId_thenError() {
		provider.getPrivateKeyId();
	}
}
