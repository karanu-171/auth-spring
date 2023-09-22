package com.karanu.authentication.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KET = "fEOIw4Y+H0oAu7BYtOz6I59syUE/tOw5UyvCE2GsZhktLwfQwwu/m9/u6VEQ3JTO\n";
    public String extractUserEmail(String token) {
        return null;
    }
    public <T> T extractionClaim(String token, Function<Claims, T>claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
