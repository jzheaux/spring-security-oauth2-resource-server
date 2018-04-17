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
package org.springframework.security.oauth2.core;

import java.util.Map;

/**
 * Implementations of this interface are responsible for &quot;verifying&quot;
 * the validity and/or constraints of the attributes contained in an OAuth 2.0 Token.
 *
 * @author Joe Grandja
 * @since 5.1
 */
public interface OAuth2TokenVerifier {

	/**
	 * Verify the validity and/or constraints of the provided OAuth 2.0 Token attributes.
	 *
	 * @param tokenAttributes a {@code Map} of the token attributes
	 * @throws OAuth2AuthenticationException if an error occurs while attempting to verify the token attributes
	 */
	void verify(Map<String, Object> tokenAttributes) throws OAuth2AuthenticationException;

}
