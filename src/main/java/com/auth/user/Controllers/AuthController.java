package com.auth.user.Controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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

    @PostMapping(value = "/signin")
    public ResponseEntity<?> authenticateUser( 
//    @RequestParam(required = false) MultiValueMap<String, String> paramMap
            @RequestBody @ModelAttribute("users") LoginRequest loginRequest
    )
    {

        String username;
        String password;

        username = loginRequest.getUsername();
        password = loginRequest.getPassword();

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

        // Determine the redirect URL based on the user's roles
        String defaultUrl = "/user";  // Default URL for standard users
        for (GrantedAuthority authority : userDetails.getAuthorities()) {
            if (authority.getAuthority().equals("ROLE_ADMIN")) {
                defaultUrl = "/admin";  // Redirect URL for admins
                break;
            }
        }

        // Create a response body that includes the token and redirect URL
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("token", jwtToken);
        responseBody.put("redirectUrl", defaultUrl);

        // Return the response as a JSON object
        return ResponseEntity.ok(responseBody);
    }
}
