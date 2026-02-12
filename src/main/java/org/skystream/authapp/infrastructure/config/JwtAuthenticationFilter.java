package org.skystream.authapp.infrastructure.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.skystream.authapp.domain.entity.UserEntity;
import org.skystream.authapp.domain.service.JwtService;
import org.skystream.authapp.domain.service.TokenBlacklistService;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // If no token is present, let the chain continue.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract Token and Claims
        jwt = authHeader.substring(7);

        // Blacklist Check: If the token is blacklisted, we reject it immediately.
        if (tokenBlacklistService.isBlacklisted(jwt)) {
            log.warn("Blocked request with Blacklisted Token: {}", jwt.substring(0, 10) + "...");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token is logged out (Blacklisted)");
            return;
        }

        try {
            userEmail = jwtService.extractEmail(jwt);

            // If we have an email, and the context is not already set
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Load the User from DB
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // We assume UserDetails can be cast to our UserEntity to access custom fields.
                // If you use a wrapper, adjust this casting.
                if (userDetails instanceof UserEntity userEntity) {

                    String tokenStamp = jwtService.extractSecurityStamp(jwt);
                    String dbStamp = userEntity.getSecurityStamp();

                    // If the password changed, this token MUST be rejected immediately
                    if (dbStamp != null && !dbStamp.equals(tokenStamp)) {
                        log.warn("Revoked Token Attempt: Security Stamps do not match for user {}", userEmail);
                        // We do not set the context. The request will fail 403 Forbidden.
                        filterChain.doFilter(request, response);
                        return;
                    }
                }

                // Standard Validation
                if (jwtService.isAccessTokenValid(jwt, userDetails.getUsername())) {

                    // Create the Auth Token for Spring Context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // "Log In" the user for this request only
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            log.error("JWT Authentication failed: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
