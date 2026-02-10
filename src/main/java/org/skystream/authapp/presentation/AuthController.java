package org.skystream.authapp.presentation;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.skystream.authapp.application.AuthService;
import org.skystream.authapp.application.request.ForgotPasswordRequest;
import org.skystream.authapp.application.request.LoginRequest;
import org.skystream.authapp.application.request.RegisterRequest;
import org.skystream.authapp.application.request.ResetPasswordRequest;
import org.skystream.authapp.application.response.AuthenticationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        authService.registerPassenger(request);

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body("Registration successful. Please check your email to verify your account.");
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok("Account verified successfully! You may now login.");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.initiatePasswordReset(request);
        return ResponseEntity.ok("If an account exists for this email, a password reset link has been sent.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.completePasswordReset(request);
        return ResponseEntity.ok("Password has been successfully reset. You may now login.");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody Map<String, String> request) {
        String requestRefreshToken = request.get("refreshToken");
        return ResponseEntity.ok().build();
    }

}