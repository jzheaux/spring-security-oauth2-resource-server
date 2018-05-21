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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Some lightweight support for pem encoding. Check out Bouncy Castle for more
 * full-fledged support.
 *
 * @author Josh Cummings
 */
public final class Pem {
	public static final String X509_PEM_HEADER_SEGMENT = "PUBLIC KEY";
	public static final String PKCS8_PEM_HEADER_SEGMENT = "PRIVATE KEY";

	public static byte[] decode(String description, InputStream pemEncoded) {
		try ( BufferedReader reader = new BufferedReader(new InputStreamReader(pemEncoded)) ) {
			byte[] encoded =
					reader.lines()
							.filter(line -> !line.contains(description))
							.collect(Collectors.joining(""))
							.getBytes();

			return Base64.getDecoder().decode(encoded);
		} catch ( Exception e ) {
			throw new IllegalStateException(e);
		}
	}

	public static void encode(String description, byte[] key, OutputStream destination) {
		try ( PrintWriter write = new PrintWriter(new OutputStreamWriter(destination)) ) {
			write.print("-----BEGIN " + description + "-----");
			byte[] bits = Base64.getEncoder().encode(key);
			for ( int i = 0; i < bits.length; i++ ) {
				if ( i % 64 == 0 ) {
					write.println();
				}
				write.write(bits[i]);
			}
			write.println();
			write.println("-----END " + description + "-----");
		}
	}
}
