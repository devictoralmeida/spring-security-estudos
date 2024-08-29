package com.devictoralmeida.eazybank.config;

//@Component
//@RequiredArgsConstructor
//@Profile("prod") // Esse bean só será carregado se o profile ativo for "prod"
//public class CustomAuthenticationProviderProd implements AuthenticationProvider {
//  private final UserDetailsService userDetailsService;
//  private final PasswordEncoder passwordEncoder;
//
//  @Override
//  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//    // 1º Precisamos carregar o UserDetails
//    String username = authentication.getName();
//    String password = authentication.getCredentials().toString();
//    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//    // Vamos comparar agora as senhas:
//    if (passwordEncoder.matches(password, userDetails.getPassword())) {
//      // Aqui podemos ter lógicas adicionais para autenticar o usuário, ex: autenticar apenas se for +18 anos.
//      return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
//    } else {
//      throw new BadCredentialsException("Credenciais inválidas");
//    }
//  }
//
//  @Override
//  public boolean supports(Class<?> authentication) {
//    // Copiando a lógica do DaoAuthenticationProvider
//    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
//  }
//}
