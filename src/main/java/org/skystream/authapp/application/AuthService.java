package org.skystream.authapp.application;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.skystream.authapp.application.request.ForgotPasswordRequest;
import org.skystream.authapp.application.request.LoginRequest;
import org.skystream.authapp.application.request.RegisterRequest;
import org.skystream.authapp.application.request.ResetPasswordRequest;
import org.skystream.authapp.application.response.AuthenticationResponse;
import org.skystream.authapp.domain.entity.RoleEntity;
import org.skystream.authapp.domain.entity.UserEntity;
import org.skystream.authapp.domain.event.PasswordResetRequestedEvent;
import org.skystream.authapp.domain.event.UserRegisteredEvent;
import org.skystream.authapp.domain.repository.RoleRepository;
import org.skystream.authapp.domain.repository.UserRepository;
import org.skystream.authapp.domain.service.JwtService;
import org.skystream.authapp.domain.service.RefreshTokenService;
import org.skystream.authapp.domain.service.TokenBlacklistService;
import org.skystream.authapp.domain.types.AccountStatus;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final ApplicationEventPublisher eventPublisher;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    @Transactional
    public void registerPassenger(RegisterRequest request) {
        log.info("Processing registration for email: {}", request.getEmail());

        // Validation: Uniqueness Check
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email is already registered");
        }

        // We assign 'PASSENGER' based on RBAC Integration Logic
        RoleEntity passengerRole = roleRepository.findByName("PASSENGER")
                .orElseThrow(() -> new RuntimeException(
                        "Critical System Error: Default Role 'PASSENGER' not found. Check Seeder."
                ));

        // Entity Construction
        UserEntity newUser = UserEntity.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .roles(Set.of(passengerRole))
                .accountStatus(AccountStatus.PENDING)
                .isEmailVerified(false)
                .build();

        // Persistence
        UserEntity savedUser = userRepository.save(newUser);
        log.info("User persisted with ID: {} | Status: PENDING", savedUser.getId());

        // Token Generation (Stateless)
        String actionToken = jwtService.generateVerificationToken(savedUser.getId(), savedUser.getEmail());

        // We assume the event listener handles the actual delivery simulation.
        eventPublisher.publishEvent(new UserRegisteredEvent(this, savedUser, actionToken));
    }

    @Transactional
    public void verifyEmail(String token) {
        // Cryptographic Validation (Signature, Expiration & Action Claim)
        if (!jwtService.isTokenValid(token, "VERIFY_EMAIL")) {
            throw new RuntimeException("Invalid or Expired Verification Token");
        }

        // Extract Identity
        String userId = jwtService.extractUserId(token);
        String tokenEmail = jwtService.extractEmail(token);

        UserEntity user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Integrity Check
        if (!user.getEmail().equals(tokenEmail)) {
            throw new RuntimeException("Token invalid: Email address does not match");
        }

        // Idempotency Check
        if (user.getAccountStatus() == AccountStatus.ACTIVE) {
            log.info("User {} already verified.", user.getEmail());
            return;
        }

        // Activate The State
        user.setEmailVerified(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        user.setSecurityStamp(java.util.UUID.randomUUID().toString());

        userRepository.save(user);
        log.info("User {} successfully verified and ACTIVATED.", user.getEmail());
    }

    public void initiatePasswordReset(ForgotPasswordRequest request) {
        log.info("Password reset requested for email: {}", request.getEmail());

        userRepository.findByEmail(request.getEmail()).ifPresent(user -> {

            String resetToken = jwtService.generatePasswordResetToken(user);
            eventPublisher.publishEvent(new PasswordResetRequestedEvent(this, user, resetToken));
        });

    }

    @Transactional
    public void completePasswordReset(ResetPasswordRequest request) {
        String token = request.getToken();

        if (!jwtService.isTokenValid(token, "RESET_PASSWORD")) {
            throw new RuntimeException("Invalid or Expired Reset Token");
        }

        String userId = jwtService.extractUserId(token);
        String tokenStamp = jwtService.extractSecurityStamp(token);

        UserEntity user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        String dbStamp = user.getSecurityStamp();
        if (dbStamp == null || !dbStamp.equals(tokenStamp)) {
            throw new RuntimeException("Token has been revoked or used.");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setSecurityStamp(java.util.UUID.randomUUID().toString());


        userRepository.save(user);

        log.info("Password successfully reset for user ID: {}", user.getId());
    }

    public AuthenticationResponse login(LoginRequest request) {
        // Triggers the UserDetailsService -> loads user -> checks Bcrypt hash.
        // If password fails, Throws BadCredentialsException automatically.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        // Load User Entity
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("User not found after authentication.")); // Should never happen if step 1 passed.

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user.getId());

        // Build Response
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(900) // 15 minutes in seconds (informational for frontend)
                .build();
    }

    public void logout(String authHeader, String refreshToken) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwt = authHeader.substring(7);

            Date expiresAt = jwtService.extractExpiration(jwt);
            long ttl = expiresAt.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                tokenBlacklistService.blacklistToken(jwt, ttl);
            }
        }

        if (refreshToken != null) {
            refreshTokenService.revokeRefreshToken(refreshToken);
        }
    }

    public String refreshToken(String requestRefreshToken){
        return refreshTokenService.rotateRefreshToken(requestRefreshToken);
    }
}
