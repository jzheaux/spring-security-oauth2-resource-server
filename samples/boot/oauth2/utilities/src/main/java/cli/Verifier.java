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

package cli;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderLocalKeySupport;
import org.springframework.security.oauth2.jwt.SingleKeyProvider;
import support.Keys;

import java.security.Key;
import java.util.Map;

public class Verifier {
	public static class KeyConverter implements IStringConverter<Key> {
		@Override
		public Key convert(String value) {
			return Keys.x509(new FileSystemResource(value));
		}
	}

	@Parameter(names = { "-with" }, converter = KeyConverter.class, required = true)
	Key verify;

	@Parameter(names = { "-jwt" }, required = true)
	String jwt;

	public Map<String, Object> run() {
		SingleKeyProvider provider = () -> this.verify;

		Jwt decoded = new NimbusJwtDecoderLocalKeySupport(provider).decode(jwt);

		return decoded.getClaims();
	}

	public static void main(String[] args) {
		Verifier verifier = new Verifier();
		JCommander.newBuilder()
				.addObject(verifier)
				.build()
				.parse(args);

		System.out.println(verifier.run());
	}
}
