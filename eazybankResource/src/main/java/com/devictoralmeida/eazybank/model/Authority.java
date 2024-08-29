package com.devictoralmeida.eazybank.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

@Entity
@Table(name = "authorities")
@Getter
@Setter
public class Authority implements Serializable {
  @Serial
  private static final long serialVersionUID = -3051006847466913632L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;

  private String name;

  @ManyToOne
  @JoinColumn(name = "customer_id")
  private Customer customer;
}
