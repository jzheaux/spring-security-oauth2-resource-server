package org.springframework.messages;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;

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
	public void setUp() throws IOException {
		messageBothAuthority =
			IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("message-both"));

		messageReadAuthority =
			IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("message-read"));

		messageWriteAuthority =
			IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("message-write"));
	}

	@Test
	public void whenProperAuthorizationHeader_thenAllowBoth() {
		Message toSave = new Message("New");

		ResponseEntity<Message> response = postForMessage("/messages", messageBothAuthority, toSave);

		Message saved = response.getBody();
		assertThat(saved.getText()).isEqualTo(toSave.getText());

		response = getForMessage("/messages/{id}", messageBothAuthority, saved.getId());
		Message message = response.getBody();

		assertThat(message.getText()).isEqualTo(saved.getText());
	}

	@Test
	public void whenProperAuthorizationHeader_thenAllowGet() {
	    ResponseEntity<Message> response = getForMessage("/messages/{id}", messageReadAuthority, 1L);

		Message message = response.getBody();

		assertThat(message.getText()).isEqualTo("Hello World");
	}

	@Test
	public void whenProperAuthorizationHeader_thenAllowPost() {
		Message toSave = new Message("New");

		ResponseEntity<Message> response = postForMessage("/messages", messageWriteAuthority, toSave);

		Message saved = response.getBody();
		assertThat(saved.getText()).isEqualTo(toSave.getText());

		response = getForMessage("/messages/{id}", messageReadAuthority, saved.getId());
		Message message = response.getBody();

		assertThat(message.getText()).isEqualTo(saved.getText());
	}

	@Test
	public void whenNoAuthorizationHeaderOnRead_denyWith401() {
		ResponseEntity<Message> response = getForMessage("/messages/{id}", null, 1L);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void whenNoAuthorizationHeaderOnWrite_denyWith401() {
		Message toSave = new Message("New");
		ResponseEntity<Message> response = postForMessage("/messages", null, toSave);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void whenBadAuthorizationHeaderOnRead_denyWith403() {
		ResponseEntity<Message> response = getForMessage("/messages/{id}", messageWriteAuthority, 1L);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void whenBadAuthorizationHeaderOnWrite_denyWith403() {
		Message toSave = new Message("New");
		ResponseEntity<Message> response = postForMessage("/messages", messageReadAuthority, toSave);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
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
