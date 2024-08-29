package com.devictoralmeida.eazybank.config;

import com.devictoralmeida.eazybank.filters.RequestValidationBeforeFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@Profile("!prod") // Esse bean só será carregado se o profile ativo for DIFERENTE de "prod"
public class ProjectSecurityConfig {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // Protegendo rotas específicas e liberando outras
//    http.authorizeHttpRequests(requests -> requests.requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
//            .requestMatchers("/notices", "/contact", "/error", "/register", "/login").permitAll()
//    );

    // Section 9 - Liberando as rotas de acordo com a Authority.
    http.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
//            .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
//            .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
            // filtros JWT
//            .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
//            .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
            .authorizeHttpRequests(requests ->
                            // Quando há mais de uma authority, usa-se o hasAnyAuthority OU hasAnyRole
                            requests
//                    .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//                    .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")
//                    .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
//                    .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                                    .requestMatchers("/myAccount").hasRole("USER") // O prefixo ROLE_ é adicionado automaticamente
                                    .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                                    .requestMatchers("/myLoans").hasRole("USER")
                                    .requestMatchers("/myCards").hasRole("USER")
                                    .requestMatchers("/user").authenticated()
                                    .requestMatchers("/notices", "/contact", "/error", "/register", "/login", "apiLogin").permitAll()
            );

    // Desabilitando autenticação por formulário e autenticação básica
    // http.formLogin(formLoginConfigurer -> formLoginConfigurer.disable());
    // http.httpBasic(httpBasicConfigurer -> httpBasicConfigurer.disable());

//    http.formLogin(withDefaults());
    //    http.httpBasic(withDefaults());

    http.csrf(csrfConfigurer -> csrfConfigurer.disable());

    // Section 7 --> Instanciando nossa classe CustomBasicAuthenticationEntryPoint
//    http.httpBasic(basicConfigurer -> basicConfigurer.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
//    http.sessionManagement(sessionManagement -> {
//      sessionManagement
//              .invalidSessionUrl("/login")
//              .maximumSessions(1)
//              .maxSessionsPreventsLogin(true)
//              .expiredUrl("/login");
//    });

    // Sessão 11 - JWT
    // Removendo o JSESSIONID (Cookie), pois o token será enviado no header pelo front
    http.sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

    http.oauth2ResourceServer(resourceServerConfig -> resourceServerConfig
            .jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));

    return http.build();
  }

//  @Bean
//  public UserDetailsService userDetailsService() {
//    UserDetails user = User.withUsername("user")
//            .password("{noop}12345") // NoOp
//            .authorities("read")
//            .build();
//    UserDetails admin = User.withUsername("admin")
//            .password("{bcrypt}$2a$12$HTQp1fuQiBSckSs4SAwLUOP6soLkib5j0hxWii028y/hTJcBpJRZK") //BCrypt
//            .authorities("admin")
//            .build();
//    return new InMemoryUserDetailsManager(user, admin);
//  }

//  @Bean
//  public PasswordEncoder passwordEncoder() {
//    // Ao acessar o método abaixo, veremos quais são os tipos de encoders(codificadores) disponíveis, o default / recomendado pelo Security é o BCrypt
//    // Sem mencionar o prefixo da senha com { }, será usado o BCrypt
//    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//  }

//  @Bean
//  public CompromisedPasswordChecker compromisedPasswordChecker() {
//    return new HaveIBeenPwnedRestApiPasswordChecker();
//  }

  // Seção de banco de dados
  //  @Bean
  //  public UserDetailsService userDetailsService(DataSource dataSource) {
  //    return new JdbcUserDetailsManager(dataSource);
  //  }

  // Sessão 11 - JWT
//  @Bean
//  public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
//    CustomAuthenticationProvider customAuthenticationProvider = new CustomAuthenticationProvider(userDetailsService, passwordEncoder);
//    ProviderManager providerManager = new ProviderManager(customAuthenticationProvider);
//    providerManager.setEraseCredentialsAfterAuthentication(false);
//    return providerManager;
//  }
}
