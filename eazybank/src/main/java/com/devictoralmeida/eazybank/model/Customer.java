package com.devictoralmeida.eazybank.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "customer")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Customer implements Serializable {
  @Serial
  private static final long serialVersionUID = -6535146825028859494L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "customer_id")
  private Long id;

  private String name;
  private String email;

  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  private String pwd;

  @Column(name = "mobile_number")
  private String mobileNumber;

  private String role;

  @OneToMany(mappedBy = "customer", fetch = FetchType.EAGER)
  @JsonIgnore // Esse dado não será retornado no JSON para o Frontend
  private Set<Authority> authorities;

  @Column(name = "create_dt")
  @JsonIgnore
  private Date createDt;
}
