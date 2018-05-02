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

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class MessagesApplicationTests {

	@Autowired
	TestRestTemplate rest;

	String messageBothAuthority;
	String messageReadAuthority;
	String messageWriteAuthority;

	@Before
	public void setUp() throws Exception {
		this.messageBothAuthority =
			IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("message-both"));

		this.messageReadAuthority =
			IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("message-read"));

		this.messageWriteAuthority =
			IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("message-write"));
	}

	@Test
	public void requestWhenProperAuthorizationHeaderThenBothRequestsAreAllowed() throws Exception {
		Message toSave = new Message("New");

		ResponseEntity<Message> response = postForMessage("/messages", this.messageBothAuthority, toSave);

		Message saved = response.getBody();
		assertThat(saved.getText()).isEqualTo(toSave.getText());

		response = getForMessage("/messages/{id}", this.messageBothAuthority, saved.getId());
		Message message = response.getBody();

		assertThat(message.getText()).isEqualTo(saved.getText());
	}

	@Test
	public void readWhenProperAuthorizationHeaderThenGetIsAllowed() {
		ResponseEntity<Message> response = getForMessage("/messages/{id}", this.messageReadAuthority, 1L);

		Message message = response.getBody();

		assertThat(message.getText()).isEqualTo("Hello World");
	}

	@Test
	public void writeWhenProperAuthorizationHeaderThenPostIsAllowed() {
		Message toSave = new Message("New");

		ResponseEntity<Message> response = postForMessage("/messages", this.messageWriteAuthority, toSave);

		Message saved = response.getBody();
		assertThat(saved.getText()).isEqualTo(toSave.getText());

		response = getForMessage("/messages/{id}", this.messageReadAuthority, saved.getId());
		Message message = response.getBody();

		assertThat(message.getText()).isEqualTo(saved.getText());
	}

	@Test
	public void readWhenNoAuthorizationHeaderThenRequestIsUnauthorized() {
		ResponseEntity<Message> response = getForMessage("/messages/{id}", null, 1L);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(response.getHeaders().get("WWW-Authenticate"))
				.isNotNull()
				.contains("Bearer realm=\"oauth2-resource\", error=\"unauthorized\", error_description=\"Full authentication is required to access this resource\"");
	}

	@Test
	public void writeWhenNoAuthorizationHeaderThenRequestIsUnauthorized() {
		Message toSave = new Message("New");
		ResponseEntity<Message> response = postForMessage("/messages", null, toSave);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(response.getHeaders().get("WWW-Authenticate"))
				.isNotNull()
				.contains("Bearer realm=\"oauth2-resource\", error=\"unauthorized\", error_description=\"Full authentication is required to access this resource\"");
	}

	@Test
	public void readWhenAuthorizationHeaderIsMalformedThenRequestIsBadRequest() {
		ResponseEntity<Message> response = getForMessage("/messages/{id}", "a\"malformed\"token", 1L);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(response.getHeaders().get("WWW-Authenticate"))
				.isNotNull()
				.contains("Bearer realm=\"oauth2-resource\", error=\"invalid_token\", error_description=\"The token was expected to have 3 parts, but got 1.\"");
	}

	@Test
	public void writeWhenAuthorizationHeaderIsMalformedThenRequestIsBadRequest() {
		Message toSave = new Message("New");
		ResponseEntity<Message> response = postForMessage("/messages", "a\"malformed\"token", toSave);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(response.getHeaders().get("WWW-Authenticate"))
				.isNotNull()
				.contains("Bearer realm=\"oauth2-resource\", error=\"invalid_token\", error_description=\"The token was expected to have 3 parts, but got 1.\"");
	}

	@Test
	public void readWhenBadAuthorizationHeaderThenRequestIsForbidden() {
		ResponseEntity<Message> response = getForMessage("/messages/{id}", this.messageWriteAuthority, 1L);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(response.getHeaders().get("WWW-Authenticate"))
				.isNotNull()
				.contains("Bearer error=\"insufficient_scope\", " +
						"error_description=\"Insufficient scope for this resource\", " +
						"scope=\"message.read\"");
	}

	@Test
	public void writeWhenBadAuthorizationHeaderThenRequestIsForbidden() {
		Message toSave = new Message("New");
		ResponseEntity<Message> response = postForMessage("/messages", this.messageReadAuthority, toSave);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(response.getHeaders().get("WWW-Authenticate"))
				.isNotNull()
				.contains("Bearer error=\"insufficient_scope\", " +
						"error_description=\"Insufficient scope for this resource\", " +
						"scope=\"message.write\"");
	}

	protected ResponseEntity<Message> getForMessage(String uri, String token, Long id) {
		HttpHeaders headers = new HttpHeaders();

		if ( token != null ) {
			headers.add("Authorization", "Bearer " + token);
		}

		HttpEntity<?> entity = new HttpEntity<>(headers);

		return this.rest.exchange(uri, HttpMethod.GET, entity, Message.class, id);
	}

	protected ResponseEntity<Message> postForMessage(String uri, String token, Message body) {
		HttpHeaders headers = new HttpHeaders();

		if ( token != null ) {
			headers.add("Authorization", "Bearer " + token);
		}

		headers.add("Content-Type", "application/json");
		headers.add("Accept", "application/json");

		HttpEntity<?> entity = new HttpEntity<>(body, headers);

		return this.rest.exchange(uri, HttpMethod.POST, entity, Message.class);
	}
}
