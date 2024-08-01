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
        user.setUsername("alex");
        String passRaw = "imani2001";
        String passEncod = passwordEncoder.encode(passRaw);
        user.setPassword(passEncod);

        User user1 = new User();
        user1.setUsername("yami");
        String passRaw2 = "yami2000";
        String passEncod2 = passwordEncoder.encode(passRaw2);
        user1.setPassword(passEncod2);

        userRepo.save(user);
        userRepo.save(user1);
    }

    @Test
    public void insertRole() {
        Role role = new Role();
        // role.setName("USER");

        Role role2 = new Role();
        // role2.setName("ADMIN");

        roleRepo.save(role);
        roleRepo.save(role2);
    }

}
