package org.skystream.authapp.domain.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.skystream.authapp.domain.entity.RefreshTokenEntity;
import org.skystream.authapp.domain.entity.UserEntity;
import org.skystream.authapp.domain.repository.RefreshTokenRepository;
import org.skystream.authapp.domain.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    // Source: "configurable expiration windows" [2]
    @Value("${jwt.expiration.refresh}")
    private long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Transactional
    public String createRefreshToken(UUID userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generate High-Entropy Raw Token
        String rawToken = UUID.randomUUID().toString();

        // Create the Entity
        // Note: We assign a BRAND NEW Family ID here.
        RefreshTokenEntity tokenEntity = RefreshTokenEntity.builder()
                .user(user)
                .tokenHash(hashToken(rawToken))
                .familyId(UUID.randomUUID())
                .expiresAt(Instant.now().plusMillis(refreshTokenDurationMs))
                .isRevoked(false)
                .build();

        refreshTokenRepository.save(tokenEntity);

        return rawToken; // Return the raw key to the user
    }

    @Transactional
    public String rotateRefreshToken(String rawOldToken) {
        // Hash the incoming raw token so we can look it up
        String hashedToken = hashToken(rawOldToken);

        // Find the token in the DB
        RefreshTokenEntity oldToken = refreshTokenRepository.findByTokenHash(hashedToken)
                .orElseThrow(() -> new RuntimeException("Invalid Refresh Token"));


        // NOTE: CRITICAL SECURITY CHECK
        // If a malicious actor steals a refresh token... invalidate the whole family
        if (oldToken.isRevoked()) {
            log.error("SECURITY ALERT: Reuse of revoked token detected. Family ID: {}", oldToken.getFamilyId());
            log.error("Action: Invalidating all sessions for this family.");

            // The Nuclear Option: Kill the entire family
            revokeFamily(oldToken.getFamilyId());

            throw new RuntimeException("Security Breach: Token reuse detected. Session terminated.");
        }

        // Expiration Check
        if (!oldToken.isValid()) {
            throw new RuntimeException("Refresh token expired");
        }

        // Mark the Old Token as Used
        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);

        // Generate the New Token
        String rawNewToken = UUID.randomUUID().toString();

        RefreshTokenEntity newToken = RefreshTokenEntity.builder()
                .user(oldToken.getUser())
                .tokenHash(hashToken(rawNewToken))
                .familyId(oldToken.getFamilyId()) // CRITICAL: We pass the Old Family ID to the NEW Token
                .expiresAt(Instant.now().plusMillis(refreshTokenDurationMs))
                .isRevoked(false)
                .build();

        refreshTokenRepository.save(newToken);

        return rawNewToken;
    }

    @Transactional
    public void revokeUserSessions(UserEntity user) {
        refreshTokenRepository.revokeAllByUser(user);
    }

    private void revokeFamily(UUID familyId) {
        refreshTokenRepository.findByFamilyId(familyId)
                .forEach(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 Algorithm not found", e);
        }
    }
}
