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

package support;

import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static support.Pem.PKCS8_PEM_HEADER_SEGMENT;
import static support.Pem.X509_PEM_HEADER_SEGMENT;

/**
 * Targeted support for generating keypairs and writing them out to the
 * specified location, ostensibly on the filesystem.
 *
 * @author Josh Cummings
 */
public class KeyPairs {
	private KeyPair pair;

	public static KeyPairs rsa256() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);

			KeyPairs pairs = new KeyPairs();

			pairs.pair = generator.generateKeyPair();

			return pairs;
		} catch ( NoSuchAlgorithmException rsaMissing ) {
			throw new IllegalStateException(rsaMissing);
		}
	}

	public KeyPairs x509(OutputStream os) {
		Pem.encode(X509_PEM_HEADER_SEGMENT, pair.getPublic().getEncoded(), os);
		return this;
	}

	public KeyPairs pkcs8(OutputStream os) {
		Pem.encode(PKCS8_PEM_HEADER_SEGMENT, pair.getPrivate().getEncoded(), os);
		return this;
	}
}
