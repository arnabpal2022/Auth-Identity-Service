package org.skystream.authapp.infrastructure.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data // Generates Getters/Setters (Required for binding)
@Configuration
@ConfigurationProperties(prefix = "app.security")
public class AppSecurityProperties {

    private String blacklistType = "sql";

}
