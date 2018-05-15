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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class LegacyAuth0Application {

	@Bean
	public MethodSecurityExpressionHandler expressionHandler() {
		return new OAuth2MethodSecurityExpressionHandler();
	}

	@EnableResourceServer
	class WebSecurityConfig extends ResourceServerConfigurerAdapter {

		@Autowired
		PublicKey verify;

		@Bean
		AuthenticationEntryPoint entryPoint() {
			OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint() {
				@Override
				protected ResponseEntity<?> enhanceResponse(ResponseEntity<?> response, Exception exception) {
					ResponseEntity<?> enhanced = super.enhanceResponse(response, exception);

					HttpHeaders headers = new HttpHeaders();

					headers.putAll(enhanced.getHeaders());
					headers.setContentLength(0);

					return new ResponseEntity<>(headers, enhanced.getStatusCode());
				}
			};
			entryPoint.setRealmName("oauth2-resource");

			return entryPoint;
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			JwtTokenStore store = new JwtTokenStore(converter());

			resources.tokenStore(store);
			resources.authenticationEntryPoint(entryPoint());
		}

		@Bean
		JwtAccessTokenConverter converter() {
			JWTVerifier verifier =
					JWT.require(Algorithm.RSA256((RSAPublicKey) this.verify, null))
							.withIssuer("rob").build();

			return new LegacyAuth0JwtAccessTokenConverter(verifier);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(LegacyAuth0Application.class, args);
	}
}
