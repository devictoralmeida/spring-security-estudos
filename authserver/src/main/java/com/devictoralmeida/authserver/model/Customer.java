package com.devictoralmeida.authserver.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Set;

@Entity
@Getter
@Setter
public class Customer implements Serializable {
  @Serial
  private static final long serialVersionUID = 1208448354891342310L;
  
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "customer_id")
  private long id;

  private String name;

  private String email;

  @Column(name = "mobile_number")
  private String mobileNumber;

  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  private String pwd;

  private String role;

  @Column(name = "create_dt")
  @JsonIgnore
  private Date createDt;

  @OneToMany(mappedBy = "customer", fetch = FetchType.EAGER)
  @JsonIgnore
  private Set<Authority> authorities;
}
