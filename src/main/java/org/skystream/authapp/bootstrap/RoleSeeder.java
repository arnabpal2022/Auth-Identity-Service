package org.skystream.authapp.bootstrap;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.skystream.authapp.domain.entity.PermissionEntity;
import org.skystream.authapp.domain.entity.RoleEntity;
import org.skystream.authapp.domain.repository.PermissionRepository;
import org.skystream.authapp.domain.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class RoleSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Override
    @Transactional
    public void run(String... args) {
        log.info("<-- Starting MVP RBAC Seeding -->");

        PermissionEntity pFlightSearch = createPermissionIfNotFound("flight", "search");
        PermissionEntity pProfileUpdate = createPermissionIfNotFound("profile", "update");
        PermissionEntity pAuditRead = createPermissionIfNotFound("audit", "read");

        createRoleIfNotFound("PASSENGER", Set.of(pFlightSearch, pProfileUpdate));
        createRoleIfNotFound("ADMIN", Set.of(pFlightSearch, pProfileUpdate, pAuditRead));

        log.info("<-- MVP RBAC Seeding Completed -->");
    }


    private PermissionEntity createPermissionIfNotFound(String resource, String action) {
        String slug = resource + ":" + action;

        return permissionRepository.findBySlug(slug).orElseGet(() -> {
            log.info("Seeding Permission: {}", slug);
            return permissionRepository.save(PermissionEntity.builder()
                    .resource(resource)
                    .action(action)
                    .build());
        });
    }

    private void createRoleIfNotFound(String name, Set<PermissionEntity> permissions) {
        roleRepository.findByName(name).orElseGet(() -> {
            log.info("Seeding Role: {}", name);
            return roleRepository.save(RoleEntity.builder()
                    .name(name)
                    .description("Auto-generated MVP role")
                    .permissions(permissions)
                    .build());
        });
    }
}