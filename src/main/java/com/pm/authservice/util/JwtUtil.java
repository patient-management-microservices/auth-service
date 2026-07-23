package com.pm.authservice.util;

import com.pm.authservice.enums.Role;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Component
public class JwtUtil {

    private final Key secretKey;
    @Getter
    private final long expirationMs;
    private final String issuer;
    private final String audience;

    public JwtUtil(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms:36000000}") long expirationMs,
            @Value("${jwt.issuer:auth-service}") String issuer,
            @Value("${jwt.audience:patient-management}") String audience
    ) {
        byte[] keyBytes = Base64.getDecoder().decode(secret.getBytes(StandardCharsets.UTF_8));
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
        this.issuer = issuer;
        this.audience = audience;
    }

    public String generateToken(UUID userId, String email, Role role) {
        log.debug("Generating JWT for userId={}, email={}, role={}", userId, email, role);
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject(email)
                .claim("aud", audience)
                .claim("userId", userId.toString())
                .claim("role", role.name())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(secretKey)
                .compact();
    }

    public void validateToken(String token) {
        try {
            var claims = Jwts.parser().verifyWith((SecretKey) secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!issuer.equals(claims.getIssuer()) || !audience.equals(claims.get("aud", String.class))) {
                log.warn("JWT validation failed because issuer or audience did not match expected values");
                throw new JwtException("JWT token has invalid issuer or audience");
            }
        } catch (JwtException je) {
            log.debug("JWT parsing or validation failed", je);
            throw new JwtException("Invalid JWT token", je);
        }
    }

}
