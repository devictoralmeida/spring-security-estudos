package com.devictoralmeida.securityOAUTH2.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ProjectSecurityConfig {
  @Value("${GITHUB_CLIENT_SECRET}")
  private String githubClientSecret;

  @Value("${GITHUB_CLIENT_ID}")
  private String githubClientId;

  @Value("${FACEBOOK_CLIENT_SECRET}")
  private String facebookClientSecret;

  @Value("${FACEBOOK_CLIENT_ID}")
  private String facebookClientId;

  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests.requestMatchers("/secure").authenticated().anyRequest().permitAll())
            .oauth2Login(withDefaults())
            .formLogin(withDefaults());
    return http.build();
  }

  // Vamos precisar criar um ClientRegistration para cada provedor de autenticação que queremos usar
  // Depois, vamos criar um ClientRegistrationRepository que vai conter todos os ClientRegistration
  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    ClientRegistration github = githubClientRegistration();
    ClientRegistration facebook = facebookClientRegistration();
    return new InMemoryClientRegistrationRepository(github, facebook);
  }

  private ClientRegistration githubClientRegistration() {
    return CommonOAuth2Provider.GITHUB.getBuilder("github")
            .clientId(githubClientId)
            .clientSecret(githubClientSecret).build();
  }

  private ClientRegistration facebookClientRegistration() {
    return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook")
            .clientId(facebookClientId)
            .clientSecret(facebookClientSecret).build();
  }
}
