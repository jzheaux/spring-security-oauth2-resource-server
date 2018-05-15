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

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.Collections;

/**
 * @author Thomas Darimont
 */
@Controller
public class KeycloakController {

	@PreAuthorize("hasRole('ROLE_USER')")
	@GetMapping("/protected")
	public ModelAndView protectedPage(Principal principal) {
		return new ModelAndView("app", Collections.singletonMap("principal", principal));
	}

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping("/admin")
	public ModelAndView adminPage(Principal principal) {
		return new ModelAndView("admin", Collections.singletonMap("principal", principal));
	}

	@GetMapping("/")
	public String unprotectedPage(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		return "index";
	}

	@GetMapping("/account")
	public String redirectToAccountPage(@AuthenticationPrincipal OAuth2AuthenticationToken authToken) {

		if (authToken == null) {
			return "redirect:/";
		}

		OidcUser user = (OidcUser) authToken.getPrincipal();

		// Provides a back-link to the application
		return "redirect:" + user.getIssuer() + "/account?referrer=" + user.getIdToken().getAuthorizedParty();
	}

	@PreAuthorize("hasRole('ROLE_OK')")
	@GetMapping("/ok")
	public @ResponseBody String ok() {
		return "ok";
	}
}
