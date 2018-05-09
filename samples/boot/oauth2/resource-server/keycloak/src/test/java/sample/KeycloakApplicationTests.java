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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class KeycloakApplicationTests {

	@Autowired
	MockMvc mockMvc;

	@Value("${keycloak.tokenEndpoint}") String tokenEndpoint;

	RestTemplate rest = new RestTemplate();

	//-- @Test // -- currently requires Keycloak to be up and configured in a certain way
	public void performWhenProperAuthorizationHeaderThenAllow()
		throws Exception {

		String token = this.tokenByResourceOwnerGrant("test", null, "authorized", "password");

		this.mockMvc.perform(get("/ok")
				.header("Authorization", "Bearer " + token))
				.andExpect(content().string("ok"))
				.andExpect(status().isOk());
	}

	//-- @Test // -- currently requires Keycloak to be up and configured in a certain way
	public void performWhenProperAuthorizationHeaderThenNoSessionCreated()
			throws Exception {

		String token = this.tokenByResourceOwnerGrant("test", null, "authorized", "password");

		MvcResult result =
				this.mockMvc.perform(get("/ok")
					.header("Authorization", "Bearer " + token))
					.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void performWhenMissingAuthorizationHeaderThenUnauthorized()
		throws Exception {

		this.mockMvc.perform(get("/ok"))
				.andExpect(status().isUnauthorized());
	}

	//-- @Test // -- currently requires Keycloak to be up and configured in a certain way
	public void performWhenInsufficientScopeThenForbidden()
		throws Exception {

		String token = this.tokenByResourceOwnerGrant("test", null, "unauthorized", "password");

		this.mockMvc.perform(get("/ok")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						"Bearer error=\"insufficient_scope\", " +
								"error_description=\"Resource requires any or all of these scopes [ok]\", " +
								"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\", " +
								"scope=\"ok\""));
	}

	private String tokenByResourceOwnerGrant(
			String clientId, String clientPassword,
			String resourceId, String resourcePassword) {

		String authorization = Base64.getEncoder().encodeToString((clientId + ":").getBytes());

		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Basic " + authorization);

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("grant_type", "password");
		map.add("username", resourceId);
		map.add("password", resourcePassword);

		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

		ResponseEntity<Map> response = this.rest.postForEntity(
				this.tokenEndpoint,
				request, Map.class );

		return (String) response.getBody().get("access_token");
	}
}
