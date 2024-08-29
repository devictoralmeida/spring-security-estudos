package com.devictoralmeida.eazybank.config;

//@Component
//@RequiredArgsConstructor
//@Profile("!prod") // Esse bean só será carregado se o profile ativo for DIFERENTE de "prod"
//public class CustomAuthenticationProvider implements AuthenticationProvider {
//  private final UserDetailsService userDetailsService;
//  private final PasswordEncoder passwordEncoder;
//
//  @Override
//  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//    String username = authentication.getName();
//    String password = authentication.getCredentials().toString();
//    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//    return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
//  }
//
//  @Override
//  public boolean supports(Class<?> authentication) {
//    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
//  }
//}
