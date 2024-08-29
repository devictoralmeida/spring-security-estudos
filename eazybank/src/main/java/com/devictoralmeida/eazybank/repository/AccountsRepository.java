package com.devictoralmeida.eazybank.repository;

import com.devictoralmeida.eazybank.model.Accounts;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountsRepository extends CrudRepository<Accounts, Long> {
  Accounts findByCustomerId(long customerId);
}
