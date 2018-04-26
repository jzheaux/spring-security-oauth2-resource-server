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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2ResourceServerExpressions;

import java.net.URL;

public class CustomExpressions {
	private final OAuth2ResourceServerExpressions expressions;

	public CustomExpressions(OAuth2ResourceServerExpressions expressions) {
		this.expressions = expressions;
	}

	public boolean customPermission(Authentication authentication, String... scopes) {
		URL issuer = this.expressions.issuer(authentication);
		boolean has = this.expressions.hasAnyScope(authentication, scopes);

		this.expressions.insufficientIfNot(
			has || issuer != null && issuer.getHost().equals("myhost"),
			scopes);

		return true;
	}
}
