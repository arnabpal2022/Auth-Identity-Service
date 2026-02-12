package org.skystream.authapp.domain.repository;

import org.skystream.authapp.domain.entity.BlacklistedTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedTokenEntity, UUID> {

    Optional<BlacklistedTokenEntity> findByToken(String token);

    @Modifying
    @Query("DELETE FROM BlacklistedTokenEntity b WHERE b.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") Instant now);
}
