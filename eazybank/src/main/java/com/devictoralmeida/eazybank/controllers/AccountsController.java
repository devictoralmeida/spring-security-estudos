package com.devictoralmeida.eazybank.controllers;

import com.devictoralmeida.eazybank.model.Accounts;
import com.devictoralmeida.eazybank.model.Customer;
import com.devictoralmeida.eazybank.repository.AccountsRepository;
import com.devictoralmeida.eazybank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class AccountsController {
  private final AccountsRepository accountsRepository;
  private final CustomerRepository customerRepository;

  @GetMapping("/myAccount")
  public Accounts getAccountDetails(@RequestParam String email) {
    Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);

    if (optionalCustomer.isPresent()) {
      Customer customer = optionalCustomer.get();
      Accounts accounts = accountsRepository.findByCustomerId(customer.getId());

      if (accounts != null) {
        return accounts;
      } else {
        return null;
      }

    } else {
      return null;
    }
  }
}
