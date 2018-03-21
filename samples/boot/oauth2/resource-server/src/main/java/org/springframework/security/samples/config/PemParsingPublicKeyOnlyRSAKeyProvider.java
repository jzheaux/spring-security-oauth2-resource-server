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
package org.springframework.security.samples.config;

import org.springframework.security.crypto.codec.Base64;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

/**
 * A {@link PublicKeyOnlyRSAKeyProvider} that reads in an RSA public key and converts it from
 * PEM format (i.e. Base64-encoded) into DER format.
 * <p>
 * I realize that Bouncycastle is more feature-rich, but this sufficed for me and saved me a
 * dependency.
 */
public class PemParsingPublicKeyOnlyRSAKeyProvider implements PublicKeyOnlyRSAKeyProvider {
	private static final String PUBLIC_KEY_HEADER_FOOTER_SEGMENT = "PUBLIC KEY";

	private final RSAPublicKey key;

	public PemParsingPublicKeyOnlyRSAKeyProvider(InputStream is) {
		try (Scanner keyBytes = new Scanner(is)) {

			StringBuilder sb = new StringBuilder();
			while (keyBytes.hasNextLine()) {
				String line = keyBytes.nextLine();
				if (!line.contains(PUBLIC_KEY_HEADER_FOOTER_SEGMENT)) {
					sb.append(line);
				}
			}

			byte[] decoded = Base64.decode(sb.toString().getBytes());
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			key = (RSAPublicKey) kf.generatePublic(spec);
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public RSAPublicKey getPublicKeyById(String s) {
		return key;
	}
}
