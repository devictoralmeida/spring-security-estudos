package com.devictoralmeida.eazybank.controllers;

import com.devictoralmeida.eazybank.model.Customer;
import com.devictoralmeida.eazybank.model.Loans;
import com.devictoralmeida.eazybank.repository.CustomerRepository;
import com.devictoralmeida.eazybank.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class LoansController {
  private final LoanRepository loanRepository;
  private final CustomerRepository customerRepository;

  @GetMapping("/myLoans")
  @PostAuthorize("hasRole('USER')")
  public List<Loans> getLoanDetails(@RequestParam String email) {
    Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);
    if (optionalCustomer.isPresent()) {
      List<Loans> loans = loanRepository.findByCustomerIdOrderByStartDtDesc(optionalCustomer.get().getId());
      if (loans != null) {
        return loans;
      } else {
        return null;
      }
    } else {
      return null;
    }
  }
}
