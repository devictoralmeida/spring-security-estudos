package com.devictoralmeida.eazybank.repository;

import com.devictoralmeida.eazybank.model.Loans;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {

  // @PreAuthorize("hasRole('USER')")
  List<Loans> findByCustomerIdOrderByStartDtDesc(long customerId);

}
