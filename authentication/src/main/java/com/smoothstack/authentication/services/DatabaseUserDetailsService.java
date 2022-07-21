package com.smoothstack.authentication.services;

import com.smoothstack.common.models.User;
import com.smoothstack.common.models.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.ArrayList;
import java.util.List;

/*
@Service
public class DatabaseUserDetailsService implements UserDetailsService {
    @Autowired
    RestTemplate restTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = restTemplate.getForObject("http://user/login/u/" + username, User.class);

        if (user != null) {
            org.springframework.security.core.userdetails.User.UserBuilder builder;
            builder = org.springframework.security.core.userdetails.User.withUsername(user.getUserName());
            builder.password(new BCryptPasswordEncoder().encode(user.getPassword()));

            List<String> roles = new ArrayList<String>();

            roles.add("app-user");

            for (UserRole role : user.getUserRoles())
                roles.add(role.getRoleName());

            String[] roleArray = new String[roles.size()];

            for (int i = 0; i < roles.size(); i++)
                roleArray[i] = roles.get(i);

            builder.roles(roleArray);

            return builder.build();
        }

        throw new UsernameNotFoundException("User not found");
    }
}

 */