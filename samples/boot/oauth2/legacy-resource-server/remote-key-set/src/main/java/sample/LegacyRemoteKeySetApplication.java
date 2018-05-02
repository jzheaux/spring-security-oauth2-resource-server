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

import okhttp3.mockwebserver.MockWebServer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;

/**
 * @author Josh Cummings
 */
@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class LegacyRemoteKeySetApplication {

	@Bean
	public MethodSecurityExpressionHandler expressionHandler() {
		return new OAuth2MethodSecurityExpressionHandler();
	}

	@EnableResourceServer
	class WebSecurityConfig extends ResourceServerConfigurerAdapter {
		@Autowired
		MockWebServer server;

		@Bean
		public DefaultAccessTokenConverter converter() {
			DefaultAccessTokenConverter datc = new DefaultAccessTokenConverter();
			datc.setScopeAttribute("scp");

			return datc;
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			JwkTokenStore store =
					new JwkTokenStore(
							this.server.url("/.well-known/jwks.json").toString(),
							converter());

			resources.tokenStore(store);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(LegacyRemoteKeySetApplication.class, args);
	}
}
