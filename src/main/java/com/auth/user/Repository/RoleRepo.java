package com.auth.user.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.user.Models.Role;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
