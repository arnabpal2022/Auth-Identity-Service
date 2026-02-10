package org.skystream.authapp.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.skystream.authapp.domain.types.AuthProvider;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "federated_identities",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"provider", "provider_subject_id"})
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FederatedIdentityEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "provider", nullable = false, length = 50)
    private String provider;

    @Column(name = "provider_subject_id", nullable = false)
    private String providerSubjectId;

    @Column(name = "tenant_id", length = 100)
    private String tenantId;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    // Senior Tip: Convenience method to handle Enums safely
    public AuthProvider getProviderEnum() {
        try {
            return AuthProvider.valueOf(this.provider);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
