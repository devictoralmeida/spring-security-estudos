package com.devictoralmeida.authserver.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

@Entity
@Getter
@Setter
@Table(name = "authorities")
public class Authority implements Serializable {
  @Serial
  private static final long serialVersionUID = -1980627747456992979L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;

  private String name;

  @ManyToOne
  @JoinColumn(name = "customer_id")
  private Customer customer;
}
