package org.skystream.authapp.domain.repository;

import org.skystream.authapp.domain.entity.RefreshTokenEntity;
import org.skystream.authapp.domain.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    List<RefreshTokenEntity> findByFamilyId(UUID familyId);

    List<RefreshTokenEntity> findAllByUser(UserEntity user);

    @Modifying
    @Query("UPDATE RefreshTokenEntity r SET r.isRevoked = true WHERE r.user = :user")
    void revokeAllByUser(@Param("user") UserEntity user);

    @Query("SELECT r FROM RefreshTokenEntity r WHERE r.familyId = :familyId AND r.isRevoked = false")
    List<RefreshTokenEntity> findActiveByFamilyId(@Param("familyId") UUID familyId);
}
