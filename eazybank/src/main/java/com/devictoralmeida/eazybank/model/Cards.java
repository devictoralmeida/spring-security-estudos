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
@Table(name = "cards")
public class Cards implements Serializable {
  @Serial
  private static final long serialVersionUID = -7991525665499270650L;

  @Id
  @Column(name = "card_id")
  private long cardId;

  @Column(name = "customer_id")
  private long customerId;

  @Column(name = "card_number")
  private String cardNumber;

  @Column(name = "card_type")
  private String cardType;

  @Column(name = "total_limit")
  private int totalLimit;

  @Column(name = "amount_used")
  private int amountUsed;

  @Column(name = "available_amount")
  private int availableAmount;

  @Column(name = "create_dt")
  private Date createDt;

}
