package com.smoothstack.authentication.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TestController {

    @GetMapping("/")
    public String hello(Authentication authentication) {
        return "Hello, " + authentication.getName() + "!";
    }

    @GetMapping("roles")
    public ResponseEntity getRoles(Authentication authentication) {
        return ResponseEntity.accepted().body(authentication.getAuthorities());
    }
}
