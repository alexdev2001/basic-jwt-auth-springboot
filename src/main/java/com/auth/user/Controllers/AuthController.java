package com.auth.user.Controllers;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.auth.user.Models.LoginRequest;
import com.auth.user.Models.LoginResponse;
import com.auth.user.Repository.RoleRepo;
import com.auth.user.Repository.UserRepo;
import com.auth.user.Security.UserDetailsImp1;
import com.auth.user.Security.UserDetailsImpl;
import com.auth.user.Security.Jwt.JwtUtils;

import lombok.RequiredArgsConstructor;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepo userRepo;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    RoleRepo roleRepo;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping(value = "/signin", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity<?> authenticateUser( 
    @RequestParam(required = false) MultiValueMap<String, String> paramMap) 
    {

        String username;
        String password;

        username = paramMap.getFirst("username");
        password = paramMap.getFirst("password");

        // if (loginRequest != null) {
        //     username = loginRequest.getUsername();
        //     password = loginRequest.getPassword();
        // } else if  (paramMap != null) {
        //     username = paramMap.getFirst("username");
        //     password = paramMap.getFirst("password");
        // } else {
        //     return ResponseEntity.badRequest().body("Invalid login request");
        // }

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImp1 userDetails = (UserDetailsImp1) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateJwtToken(authentication);
        List<String> roles = userDetails.getAuthorities().stream()
                                        .map(item -> item.getAuthority())
                                        .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(jwtToken, roles);

        return ResponseEntity.ok(response);
    }
}
