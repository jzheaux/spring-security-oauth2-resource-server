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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * @author Josh Cummings
 */
public abstract class AbstractKeycloakITests {

	private static GenericContainer container = new GenericContainer(
			new ImageFromDockerfile()
					.withFileFromClasspath("import-realm.json", "import-realm.json")
					.withFileFromClasspath("Dockerfile", "realm-importing.docker"));

	private RestTemplate rest = new RestTemplate();

	@Value("${spring.boot.oauth2.resourceserver.keycloak.tokenEndpoint}") String tokenEndpoint;

	@BeforeClass
	public static void setUpClass() {
		container.setPortBindings(Arrays.asList("8080:8080"));
		container.start();
	}

	@AfterClass
	public static void tearDownClass() {
		container.stop();
	}

	protected String getTokenByResourceOwnerGrant(
			String clientId,
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
