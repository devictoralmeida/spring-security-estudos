package com.devictoralmeida.eazybank.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
@Table(name = "notice_details")
public class Notice implements Serializable {
  @Serial
  private static final long serialVersionUID = -921483709197538127L;

  @Id
  @Column(name = "notice_id")
  private long noticeId;

  @Column(name = "notice_summary")
  private String noticeSummary;

  @Column(name = "notice_details")
  private String noticeDetails;

  @Column(name = "notic_beg_dt")
  private Date noticBegDt;

  @Column(name = "notic_end_dt")
  private Date noticEndDt;

  @JsonIgnore
  @Column(name = "create_dt")
  private Date createDt;

  @JsonIgnore
  @Column(name = "update_dt")
  private Date updateDt;


}
