package com.devictoralmeida.eazybank.repository;

import com.devictoralmeida.eazybank.model.AccountTransactions;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccountTransactionsRepository extends CrudRepository<AccountTransactions, String> {
  List<AccountTransactions> findByCustomerIdOrderByTransactionDtDesc(long customerId);
}
