package com.auth.user.Security.Jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.auth.user.Security.UserDetailsImp1;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;



@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private static final String SECRET_KEY = "sGFSd4/9js73kldFksjf78/j9gGS74ksjf9fGd78s/jfgSd74kl==";

    // genertate JWT
    public String generateJwtToken(Authentication authentication) {
        UserDetailsImp1 userPrincipal = (UserDetailsImp1) authentication.getPrincipal();

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userPrincipal.getUsername());
        claims.put("iast", new Date(System.currentTimeMillis()));
        claims.put("exp", new Date(System.currentTimeMillis() + 1000 * 60 * 120));

        return Jwts.builder()
                    .claims().add(claims).and()
                    .signWith(getSignInKey(), Jwts.SIG.HS256)
                    .compact();
    
    }    
  
  // get sign-in key
  private SecretKey getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

    // Extract username from jwt
    public String getUserNameFromJwt(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        
        return claims.getSubject();
    }
    

    // validate the token
    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("validate");
            Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
        
    }


}
