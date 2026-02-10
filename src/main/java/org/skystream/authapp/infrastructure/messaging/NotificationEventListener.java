package org.skystream.authapp.infrastructure.messaging;

import lombok.extern.slf4j.Slf4j;
import org.skystream.authapp.domain.event.PasswordResetRequestedEvent;
import org.skystream.authapp.domain.event.UserRegisteredEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class NotificationEventListener {

    @EventListener
    @Async
    public void handleUserRegisteredEvent(UserRegisteredEvent event) {
        String verificationUrl = "http://localhost:8080/api/v1/auth/verify?token=" + event.getVerificationToken();

        log.info("==================================================");
        log.info("[NOTIFICATION-SERVICE-MOCK] Sending Email to: {}", event.getUser().getEmail());
        log.info("Subject: Welcome to Airline Management System - Verify your Account");
        log.info("Body: Click this link to activate your account: {}", verificationUrl);
        log.info("==================================================");

        // TODO: In Phase 11 (Notification Service), replace this log with:
        // rabbitTemplate.convertAndSend("notification-queue", new EmailRequest(...));
    }

    @EventListener
    @Async
    public void handlePasswordResetRequestedEvent(PasswordResetRequestedEvent event) {
        String resetToken = event.getToken();

        log.info("==================================================");
        log.info("[NOTIFICATION-SERVICE-MOCK] Sending PASSWORD RESET Email to: {}", event.getUser().getEmail());
        log.info("Subject: Action Required: Reset your Airline Account Password");
        log.info("Warning: This link expires in 15 minutes.");
        log.info("--------------------------------------------------");
        log.info("TOKEN: {}", resetToken);
        log.info("--------------------------------------------------");
        log.info("COPY THE TOKEN ABOVE and use it in the POST /reset-password endpoint.");
        log.info("==================================================");

        // TODO: In Phase 11 (Notification Service), replace this log with:
        // rabbitTemplate.convertAndSend("notification.email", new EmailRequest(...));
    }
}
