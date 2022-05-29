package com.smoothstack.authentication.services;

import com.smoothstack.common.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    RestTemplate restTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = restTemplate.getForObject("http://user/login/" + username, User.class);

        System.out.println(user);

        if (user != null) {
            System.out.println(user.getUserName());
            System.out.println(user.getPassword());

            org.springframework.security.core.userdetails.User.UserBuilder builder;
            builder = org.springframework.security.core.userdetails.User.withUsername(username);
            builder.password(new BCryptPasswordEncoder().encode(user.getPassword()));
            builder.roles(new String[] {"app"});

            return builder.build();
        }

        throw new UsernameNotFoundException("User not found");
    }
}
