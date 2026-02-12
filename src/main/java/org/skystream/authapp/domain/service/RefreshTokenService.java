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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.TransactionDefinition;

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
    private final PlatformTransactionManager transactionManager;

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
        String hashedToken = hashToken(rawOldToken);
        RefreshTokenEntity oldToken = refreshTokenRepository.findByTokenHash(hashedToken)
                .orElseThrow(() -> new RuntimeException("Invalid Refresh Token"));

        if (oldToken.isRevoked()) {
            log.error("SECURITY EVENT: Reuse detection triggered for Family ID: {}", oldToken.getFamilyId());

            TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);
            transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

            transactionTemplate.execute(status -> {
                refreshTokenRepository.revokeAllByFamilyId(oldToken.getFamilyId());
                return null;
            });

            throw new SecurityException("Refresh token was already used. Security Alert triggered.");
        }

        if (oldToken.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token expired");
        }

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
    public void revokeRefreshToken(String rawToken) {
        if (rawToken == null) return;

        String hashedToken = hashToken(rawToken);

        refreshTokenRepository.findByTokenHash(hashedToken)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                    log.info("Refresh token revoked for user: {}", token.getUser().getEmail());
                });
    }

    @Transactional
    public void revokeUserSessions(UserEntity user) {
        refreshTokenRepository.revokeAllByUser(user);
    }

//    private void revokeFamily(UUID familyId) {
//        refreshTokenRepository.findByFamilyId(familyId)
//                .forEach(token -> {
//                    token.setRevoked(true);
//                    refreshTokenRepository.save(token);
//                });
//    }

    private void revokeTokenFamily(UUID familyId) {
        log.error("Executing Family Revocation for ID: {}", familyId);
        refreshTokenRepository.revokeAllByFamilyId(familyId);
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
