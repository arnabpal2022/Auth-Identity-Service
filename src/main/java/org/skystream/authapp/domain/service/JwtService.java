package org.skystream.authapp.domain.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.skystream.authapp.domain.entity.UserEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration.verification}")
    private long verificationExpiration;

    @Value("${jwt.expiration.password-reset}")
    private long resetExpiration;

    @Value("${jwt.expiration.access}")
    private long accessTokenExpiration;

    // Source: "JWT Implementation with configurable expiration" [Source 2]
    public String generateVerificationToken(UUID userId, String email) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("email", email);
        claims.put("action", "VERIFY_EMAIL");

        return buildToken(claims, userId.toString(), verificationExpiration);
    }

    public String generatePasswordResetToken(UserEntity user) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("action", "RESET_PASSWORD");
        claims.put("security_stamp", user.getSecurityStamp());

        return buildToken(claims, user.getId().toString(), resetExpiration);
    }

    public String generateAccessToken(UserEntity user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("security_stamp", user.getSecurityStamp());

        // TODO: We will inject user roles here later so the frontend knows what to show.
        // claims.put("roles", user.getRoles());

        return buildToken(claims, user.getId().toString(), accessTokenExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, String subject, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, String expectedAction) {
        try {
            final String action = extractClaim(token, claims -> claims.get("action", String.class));
            return expectedAction.equals(action) && !isTokenExpired(token);
        } catch (JwtException e) {
            // Signature failure or malformed token
            return false;
        }
    }

    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractSecurityStamp(String token) {
        return extractClaim(token, claims -> claims.get("security_stamp", String.class));
    }

    public String extractEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
