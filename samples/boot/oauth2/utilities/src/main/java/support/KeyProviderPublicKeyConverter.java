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

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.KeyProvider;

import java.security.PublicKey;
import java.util.Arrays;

public class KeyProviderPublicKeyConverter implements Converter<String, KeyProvider<PublicKey>> {
	private final PublicKeyConverter delegate = new PublicKeyConverter();

	@Override
	public KeyProvider<PublicKey> convert(String source) {
		return header -> Arrays.asList(this.delegate.convert(source));
	}
}
