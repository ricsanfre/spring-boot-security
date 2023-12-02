package com.ricsanfre.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    private static final String SECRET_KEY="616c572e4bd29e89fd9cf3536249841801e316cdbdde5f26cb9976f8f93461f6";

    public String issueToken(UserDetails userDetails) {
        return issueToken(Map.of(), userDetails);
    }

    public String issueToken(
            Map<String, Object> claims,
            UserDetails userDetails) {
        return Jwts
                .builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuer("http://ricsanfre.com")
                .issuedAt(Date.from(Instant.now()))
                .expiration(
                        Date.from(
                                Instant.now().plus(24, ChronoUnit.HOURS)
                        )
                )
                .signWith(getSigningKey())
                .compact();

    }

    public String getSubject(String token) {
        return getClaims(token).getSubject();
    }
    private Claims getClaims(String token) {
        // Parse JWT token and get Claims
        return Jwts.parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // JWTs are going to be signed using a secret (with the HMAC algorithm)
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isValidToken(String token, UserDetails userDetails) {
        String subject = getSubject(token);
        return subject.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date today = Date.from(Instant.now());
        return getClaims(token).getExpiration().before(today);
    }

}
