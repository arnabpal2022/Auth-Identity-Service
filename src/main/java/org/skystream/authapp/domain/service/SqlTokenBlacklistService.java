package org.skystream.authapp.domain.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.skystream.authapp.domain.entity.BlacklistedTokenEntity;
import org.skystream.authapp.domain.repository.BlacklistedTokenRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "app.security.blacklist-type", havingValue = "sql", matchIfMissing = true)
public class SqlTokenBlacklistService implements TokenBlacklistService {

    private final BlacklistedTokenRepository repository;

    @Override
    @Transactional
    public void blacklistToken(String token, long ttlMillis) {
        if (ttlMillis <= 0) {
            return;
        }

        if (isBlacklisted(token)) {
            return;
        }

        BlacklistedTokenEntity entity = BlacklistedTokenEntity.builder()
                .token(token)
                .expiresAt(Instant.now().plusMillis(ttlMillis))
                .build();

        repository.save(entity);
        log.debug("Token blacklisted. Expires at: {}", entity.getExpiresAt());
    }

    @Override
    public boolean isBlacklisted(String token) {
        return repository.findByToken(token).isPresent();
    }

    // The Garbage Collector.
    // Runs every hour to delete rows where 'expiresAt' is in the past.
    // Prevents the SQL table from becoming bloated with dead data.
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        repository.deleteExpiredTokens(Instant.now());
        log.info("Cleaned up expired blacklisted tokens.");
    }
}
