package com.devictoralmeida.eazybank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableJpaRepositories(basePackages = "com.devictoralmeida.eazybank.repository")
@EnableWebSecurity
public class EazybankApplication {

  public static void main(String[] args) {
    SpringApplication.run(EazybankApplication.class, args);
  }

}
