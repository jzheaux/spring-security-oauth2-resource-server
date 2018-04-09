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

package org.springframework.security.oauth2.resourceserver;

import org.junit.Test;

import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link BearerTokenAuthenticationException}.
 *
 * @author Vedran Pavic
 */
public class BearerTokenAuthenticationExceptionTests {

	private static final BearerTokenError TEST_ERROR = new BearerTokenError("test-code", HttpStatus.UNAUTHORIZED);

	private static final String TEST_MESSAGE = "test-message";

	@Test
	public void constructorWithAllParametersWhenErrorIsValidThenCreated() {
		BearerTokenAuthenticationException exception = new BearerTokenAuthenticationException(TEST_ERROR, TEST_MESSAGE,
				new Throwable());

		assertThat(exception.getError()).isEqualTo(TEST_ERROR);
	}

	@Test
	public void constructorWithAllParametersWhenErrorIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new BearerTokenAuthenticationException(null, TEST_MESSAGE, new Throwable()))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("error must not be null");
	}

	@Test
	public void constructorWithErrorAndMessageWhenErrorIsValidThenCreated() {
		BearerTokenAuthenticationException exception = new BearerTokenAuthenticationException(TEST_ERROR, TEST_MESSAGE);

		assertThat(exception.getError()).isEqualTo(TEST_ERROR);
	}

	@Test
	public void constructorWithErrorAndMessageWhenErrorIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new BearerTokenAuthenticationException(null, TEST_MESSAGE))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("error must not be null");
	}

}
