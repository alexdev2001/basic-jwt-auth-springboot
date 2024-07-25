package com.auth.user.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.user.Models.User;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
} 
