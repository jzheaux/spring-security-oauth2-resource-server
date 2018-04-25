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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Josh Cummings
 */
@SpringBootApplication
public class MessagesApplication implements BeanFactoryAware {

	private ConfigurableBeanFactory beanFactory;

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		if ( beanFactory instanceof ConfigurableBeanFactory ) {
			this.beanFactory = (ConfigurableBeanFactory) beanFactory;
		}
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {

			Map<String, Key> keys = keyPairs().entrySet().stream().collect(Collectors.toMap(
					Map.Entry::getKey,
					entry -> entry.getValue().getPublic()));

			resourceServer()
					.jwt().signature().keys(keys)

				.and().apply(http);
		}

		protected ResourceServerConfigurer resourceServer() {
			return new ResourceServerConfigurer(MessagesApplication.this.beanFactory);
		}
	}

	@Bean
	Map<String, KeyPair> keyPairs() {
		Map<String, KeyPair> keyPairs = new HashMap<>();

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);

			keyPairs.put("foo", generator.generateKeyPair());
			keyPairs.put("bar", generator.generateKeyPair());
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}

		return keyPairs;
	}

	public static void main(String[] args) {
		SpringApplication.run(MessagesApplication.class, args);
	}
}
