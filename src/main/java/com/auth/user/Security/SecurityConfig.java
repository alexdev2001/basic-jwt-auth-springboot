package com.auth.user.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfigurationSource;

import com.auth.user.Security.Jwt.AuthEntryPointJwt;
import com.auth.user.Security.Jwt.AuthTokenFilter;

import jakarta.servlet.http.HttpServlet;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // Authentication succcess handler for redirection based on roles
    @Autowired
    AuthenticationSuccesshandler authenticationSuccesshandler;

    // Authentication failure handler for when a user cannot be authentication
    @Autowired
    AuthenticationFailuireHandler authenticationFailuireHandler;

    // @Autowired
    // UserDetailsImp1 userDetailsImpl;

    // inject the user service bean
    @Autowired
    UserDetailsService userDetailsService;

    // the auth entrypoint to handle unauthorized access to a resource
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Autowired
    private CorsConfigurationSource corsConfigurationSource;

    @Bean
    public AuthTokenFilter authFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // set the authentication provider using the user details service
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    
    // set security filter
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity  http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(unauthorizedHandler))
            .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(
                authorize -> authorize
                .requestMatchers( "/login", "/admin/**", "/user/**", "/api/auth/**").permitAll()
                .requestMatchers("/admintest").hasRole("ADMIN")
                .requestMatchers("/usertest").hasRole("USER")
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
        

        http.addFilterBefore(authFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();

    }

    
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


