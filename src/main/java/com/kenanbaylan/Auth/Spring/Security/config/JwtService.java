package com.kenanbaylan.Auth.Spring.Security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "EwfJZxcgi9T1BQ443chtbMA5cl5FITxj4t37ce0hGHjRtRZcMMrtr6dvZKUlw6CJ";

    public String extractUserEmail(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return  claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
