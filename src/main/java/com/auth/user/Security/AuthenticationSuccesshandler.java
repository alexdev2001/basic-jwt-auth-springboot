package com.auth.user.Security;

import java.io.IOException;
import java.util.Collection;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthenticationSuccesshandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        
        String defaultUrl = "/user";

        for(GrantedAuthority authority : authorities) {
            if (authority.getAuthority().equals("USER")) {
                defaultUrl = "/user";
                break;
            } else if (authority.getAuthority().equals("ADMIN")) {
                defaultUrl = "/admin";
                break;
            }
        }

        response.sendRedirect(defaultUrl);
        
    }
    
}