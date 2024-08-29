package com.devictoralmeida.eazybank.controllers;

import com.devictoralmeida.eazybank.model.Contact;
import com.devictoralmeida.eazybank.repository.ContactRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

@RestController
@RequiredArgsConstructor
public class ContactsController {
  private final ContactRepository contactRepository;

  @PostMapping("/contact")
  // @PreFilter("filterObject.contactName != 'Test'")
  @PostFilter("filterObject.contactName != 'Test'")
  public List<Contact> saveContactInquiryDetails(@RequestBody List<Contact> contacts) {
    List<Contact> returnContacts = new ArrayList<>();
    if (!contacts.isEmpty()) {
      Contact contact = contacts.getFirst();
      contact.setContactId(getServiceReqNumber());
      contact.setCreateDt(new Date(System.currentTimeMillis()));
      Contact savedContact = contactRepository.save(contact);
      returnContacts.add(savedContact);
    }
    return returnContacts;
  }

  public String getServiceReqNumber() {
    Random random = new Random();
    int ranNum = random.nextInt(999999999 - 9999) + 9999;
    return "SR" + ranNum;
  }
}
