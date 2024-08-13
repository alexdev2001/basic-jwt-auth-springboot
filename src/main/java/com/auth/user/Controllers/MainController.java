package com.auth.user.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class MainController {

    @Autowired
    WebSecurityConfiguration webSecurityConfiguration;

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/login") 
    public String login() {
        return "login";
    }

    @GetMapping("/usertest")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String testUser() {
        return "usertest";
    }

    @GetMapping("/admintest")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String testAdmin() {
        return "admintest";
    }
}
