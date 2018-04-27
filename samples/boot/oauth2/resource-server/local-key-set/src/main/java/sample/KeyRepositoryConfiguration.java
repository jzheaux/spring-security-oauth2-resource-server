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
package sample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class KeyRepositoryConfiguration {

	@Bean
	public Map<String, KeyPair> sign() throws Exception {
		Map<String, KeyPair> sign = new HashMap<>();

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);

		sign.put("foo", generator.generateKeyPair());
		sign.put("bar", generator.generateKeyPair());

		return sign;
	}

	@Bean
	public Map<String, PublicKey> verify() throws Exception {
		return sign().entrySet().stream().collect(
				Collectors.toMap(
						Map.Entry::getKey,
						entry -> entry.getValue().getPublic()
				)
		);
	}
}
