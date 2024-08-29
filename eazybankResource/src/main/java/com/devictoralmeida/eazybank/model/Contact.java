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
@Table(name = "contact_messages")
public class Contact implements Serializable {
  @Serial
  private static final long serialVersionUID = 5457807799891064547L;

  @Id
  @Column(name = "contact_id")
  private String contactId;

  @Column(name = "contact_name")
  private String contactName;

  @Column(name = "contact_email")
  private String contactEmail;

  private String subject;

  private String message;

  @Column(name = "create_dt")
  private Date createDt;

}
