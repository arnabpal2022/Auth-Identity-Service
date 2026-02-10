package org.skystream.authapp.application.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    // The Short-Lived Token used for Authorization: Bearer <token> headers
    @JsonProperty("access_token")
    private String accessToken;

    // The Long-Lived Token used to request new Access Tokens
    @JsonProperty("refresh_token")
    private String refreshToken;

    // Standard OAuth2 response type
    @JsonProperty("token_type")
    @Builder.Default
    private String tokenType = "Bearer";

    @JsonProperty("expires_in")
    private long expiresIn;
}