package org.skystream.authapp;

import org.skystream.authapp.infrastructure.config.AppSecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAsync
@EnableScheduling
@EnableConfigurationProperties(AppSecurityProperties.class)
public class AuthIdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthIdentityServiceApplication.class, args);
    }

}
