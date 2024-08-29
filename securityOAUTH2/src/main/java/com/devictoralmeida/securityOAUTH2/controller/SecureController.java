package com.devictoralmeida.securityOAUTH2.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SecureController {
  @GetMapping("/secure")
  public String securePage(Authentication authentication) {
    // Em um fluxo de login normal, o objeto de autenticação é do tipo UsernamePasswordAuthenticationToken
    if (authentication instanceof UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) {
      System.out.println(usernamePasswordAuthenticationToken);
    } else if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
      // Os dados do usuário estará dentro de attributes, e baseado nos dados obtidos, podemos criar uma conta para o usuário na nossa aplicação
      System.out.println(oAuth2AuthenticationToken);
    }
    return "secure.html";
  }
}
