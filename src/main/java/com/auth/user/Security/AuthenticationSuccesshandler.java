package com.auth.user.Security;

import java.io.IOException;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.auth.user.Security.Jwt.JwtUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthenticationSuccesshandler implements AuthenticationSuccessHandler {

    @Autowired
    JwtUtils jwtUtils;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        
        String defaultUrl = "/user";

        for(GrantedAuthority authority : authorities) {
            if (authority.getAuthority().equals("ROLE_USER")) {
                defaultUrl = "/user";
                break;
            } else if (authority.getAuthority().equals("ROLE_ADMIN")) {
                defaultUrl = "/admin";
                break;
            }
        }

        String jwtToken = jwtUtils.generateJwtToken(authentication);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"token\": \"" + jwtToken + "\", \"redirectUrl\": \"" + defaultUrl + "\"}");
        response.getWriter().flush();
        
    }
    
}
