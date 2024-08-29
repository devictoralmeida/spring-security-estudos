package com.devictoralmeida.eazybank.service;

// Custom UserDetailsService
//@Service
//@RequiredArgsConstructor
//public class EazyBankUserDetailsService implements UserDetailsService {
//  private final CustomerRepository customerRepository;
//
//  @Override
//  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
//    Customer customer = customerRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
//
//    // GrantedAuthority é uma interface que representa uma autoridade concedida a um usuário
//    // List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(customer.getRole()));
//
//    // Section 9
//    List<GrantedAuthority> authorities = customer.getAuthorities().stream().map(authority ->
//            new SimpleGrantedAuthority(authority.getName())).collect(Collectors.toList());
//
//    // User é a classe que implementa UserDetails
//    return new User(customer.getEmail(), customer.getPwd(), authorities);
//  }
//}
