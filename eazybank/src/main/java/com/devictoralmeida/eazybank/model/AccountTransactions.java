package com.devictoralmeida.eazybank.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

@Entity
@Getter
@Setter
@Table(name = "account_transactions")
public class AccountTransactions implements Serializable {
  @Serial
  private static final long serialVersionUID = -7991525665499270650L;

  @Id
  @Column(name = "transaction_id")
  private String transactionId;

  @Column(name = "account_number")
  private long accountNumber;

  @Column(name = "customer_id")
  private long customerId;

  @Column(name = "transaction_dt")
  private Date transactionDt;

  @Column(name = "transaction_summary")
  private String transactionSummary;

  @Column(name = "transaction_type")
  private String transactionType;

  @Column(name = "transaction_amt")
  private int transactionAmt;

  @Column(name = "closing_balance")
  private int closingBalance;

  @Column(name = "create_dt")
  private Date createDt;

}
