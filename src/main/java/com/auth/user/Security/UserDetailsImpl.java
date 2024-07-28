package com.auth.user.Security;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.auth.user.Models.Role;
import com.auth.user.Models.User;
import com.auth.user.Repository.UserRepo;

public class UserDetailsImpl implements UserDetailsService {

    @Autowired
    UserRepo userRepo;

    @Autowired
    Role role;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user1 = userRepo.findByUsername(username);

        if(user1 == null) {
            throw new UsernameNotFoundException("could not find user");
        } 

        return org.springframework.security.core.userdetails.User.withUsername(user1.getUsername())
                        .password(user1.getPassword())
                        .authorities(user1.getRoles().stream()
                                     .map(role -> new SimpleGrantedAuthority(role.getName()))
                                     .collect(Collectors.toList()))
                                     .build();
    }
    
}
