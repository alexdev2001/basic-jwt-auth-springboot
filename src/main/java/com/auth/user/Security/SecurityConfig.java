package com.auth.user.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServlet;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    AuthenticationSuccesshandler authenticationSuccesshandler;

    @Autowired
    AuthenticationFailuireHandler authenticationFailuireHandler;

    @Autowired
    UserDetailsImpl userDetailsImpl;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity  http) throws Exception {
        http
            .authorizeHttpRequests(
                authorize -> authorize
                .requestMatchers( "/login", "/admin", "/user").permitAll()
                .anyRequest().authenticated()              
            )
            .formLogin(
                form -> form
                .loginPage("/login")
                .successHandler(authenticationSuccesshandler)
                .permitAll()
                .failureHandler(authenticationFailuireHandler)
            )
            .httpBasic(Customizer.withDefaults());
        
        return http.build();

    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


