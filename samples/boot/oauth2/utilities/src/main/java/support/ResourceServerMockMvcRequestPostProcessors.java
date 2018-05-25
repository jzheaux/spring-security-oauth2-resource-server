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

import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.JwsBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;

public class ResourceServerMockMvcRequestPostProcessors {
	/**
	 * Create a valid, signed token with mandatory attributes
	 * and add it to the request
	 *
	 * @param sign
	 * @return
	 */
	public static RequestPostProcessor bearerToken(PrivateKey sign) {
		JwsBuilder builder =
				JwsBuilder.withAlgorithm(JwsAlgorithms.RS256)
					.sign(sign);

		return request -> {
			request.addHeader("Authorization", "Bearer " + builder.build());
			return request;
		};
	}

	/**
	 * Add the given bearer token to the request
	 *
	 * @param token
	 * @return
	 */
	public static RequestPostProcessor bearerToken(String token) {
		return request -> {
			request.addHeader("Authorization", "Bearer " + token);
			return request;
		};
	}

	/**
	 * Add the given bearer token to the request
	 *
	 * @param bits
	 * @return
	 * @throws IOException
	 */
	public static RequestPostProcessor bearerToken(InputStream bits) throws IOException {
		try ( BufferedReader reader = new BufferedReader(new InputStreamReader(bits))) {
			return bearerToken(reader.readLine());
		}
	}


	/**
	 * Add the given bearer token to the request
	 *
	 * @param bits
	 * @return
	 * @throws IOException
	 */
	public static RequestPostProcessor bearerToken(Resource bits) throws IOException {
		return bearerToken(bits.getInputStream());
	}
}
