package com.auth.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.user.Models.Role;
import com.auth.user.Models.User;
import com.auth.user.Repository.RoleRepo;
import com.auth.user.Repository.UserRepo;

@SpringBootTest
public class InsertDataTest {
    @Autowired
    UserRepo userRepo;

    @Autowired
    RoleRepo roleRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    public void insertUser() {
        User user = new User();
        user.setUsername("Alex Imani");
        String passRaw = "imani2001";
        String passEncod = passwordEncoder.encode(passRaw);
        user.setPassword(passEncod);

        userRepo.save(user);
    }

    @Test
    public void insertRole() {
        Role role = new Role();
        role.setName("USER");

        Role role2 = new Role();
        role2.setName("ADMIN");

        roleRepo.save(role);
        roleRepo.save(role2);
    }

}
