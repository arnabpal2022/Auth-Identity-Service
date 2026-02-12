package org.skystream.authapp.domain.service;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
// This annotation allows us to switch between SQL and Redis via application.properties
@ConditionalOnProperty(name = "app.security.blacklist-type", havingValue = "redis")
public class RedisTokenBlacklistService implements TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;

    @Override
    public void blacklistToken(String token, long ttlMillis) {
        // We use the Token (or its hash) as the Key.
        // The Value doesn't matter ("revoked"), strictly checking existence.
        // set(key, value, timeout) handles the automatic eviction.
        redisTemplate.opsForValue().set(
                token,
                "revoked",
                Duration.ofMillis(ttlMillis)
        );
    }

    @Override
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }
}
