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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.JwsBuilder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class LocalKeySetApplicationTests {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	Map<String, KeyPair> sign;

	@Test
	public void performWhenProperAuthorizationHeaderThenAllow()
		throws Exception {

		Map.Entry<String, KeyPair> key = sign.entrySet().iterator().next();

		String token = JwsBuilder.withAlgorithm(JwsAlgorithms.RS256)
				.scope("ok")
				.sign(key.getKey(), key.getValue().getPrivate())
				.build();

		this.mockMvc.perform(get("/ok")
				.header("Authorization", "Bearer " + token))
				.andExpect(content().string("ok"))
				.andExpect(status().isOk());
	}

	@Test
	public void performWhenMissingAuthorizationHeaderThenUnauthorized()
		throws Exception {

		this.mockMvc.perform(get("/ok"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void performWhenInsufficientScopeThenForbidden()
		throws Exception {

		Map.Entry<String, KeyPair> key = sign.entrySet().iterator().next();

		String token = JwsBuilder.withAlgorithm(JwsAlgorithms.RS256)
				.sign(key.getKey(), key.getValue().getPrivate())
				.build();

		this.mockMvc.perform(get("/ok")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());
	}
}
