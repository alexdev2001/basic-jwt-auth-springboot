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
    public void insertUser1() {
        User user2 = new User();
        user2.setUsername("francis");
        String rawPass1 = "francis2024";
        String encPass1 = passwordEncoder.encode(rawPass1);
        user2.setPassword(encPass1);

        userRepo.save(user2);
    }

    @Test
    public void insertRole() {
        Role role = new Role();
        role.setName("ROLE_USER");

        Role role2 = new Role();
        role2.setName("ROLE_ADMIN");

        roleRepo.save(role);
        roleRepo.save(role2);
    }

    @Test
    public void insertRole1() {
        Role role = new Role();
        role.setName("ROLE_ADMIN");

        roleRepo.save(role);
    }

    @Test
    public void insertUser2() {
        User user3 = new User();
        user3.setUsername("austin");
        String rawpass2 = "austin2001";
        String encpass2 = passwordEncoder.encode(rawpass2);

        user3.setPassword(encpass2);

        userRepo.save(user3);
    }

}
