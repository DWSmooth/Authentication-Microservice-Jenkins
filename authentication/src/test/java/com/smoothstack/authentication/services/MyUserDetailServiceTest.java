package com.smoothstack.authentication.services;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;

@SpringBootTest
public class MyUserDetailServiceTest {
    @Autowired
    MyUserDetailsService userDetailsService;


    /*
    @Test
    void getByUserNameTest() {
        UserDetails userDetails = userDetailsService.loadUserByUsername("ben");

        System.out.println(userDetails.getUsername());
        System.out.println(userDetails.getPassword());
        System.out.println(userDetails.getAuthorities());
    }
     */
}
