package com.auth.user.Models;

import java.util.Set;

import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Component
public class LoginRequest {
    private Long user_id;
    private String username;
    private String password;

    private Set<String> role;
}
