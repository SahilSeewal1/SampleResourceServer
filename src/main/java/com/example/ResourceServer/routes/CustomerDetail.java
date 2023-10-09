package com.example.ResourceServer.routes;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@CrossOrigin
@RequestMapping("/api/customer")
public class CustomerDetail {

    @GetMapping(value="/getAllCustomerDetails")
    // @PreAuthorize("hasRole('USER')")
    public ResponseEntity getContactsById()  {
        return ResponseEntity.status(HttpStatus.OK).body("Hello world!");
    }
}


