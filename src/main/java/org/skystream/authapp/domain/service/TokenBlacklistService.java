package org.skystream.authapp.domain.service;

public interface TokenBlacklistService {

    void blacklistToken(String token, long ttlMillis);

    boolean isBlacklisted(String token);
}
