package org.skystream.authapp.domain.event;

import lombok.Getter;
import org.skystream.authapp.domain.entity.UserEntity;
import org.springframework.context.ApplicationEvent;

@Getter
public class PasswordResetRequestedEvent extends ApplicationEvent {

    private final UserEntity user;
    private final String token;

    public PasswordResetRequestedEvent(Object source, UserEntity user, String token) {
        super(source);
        this.user = user;
        this.token = token;
    }
}
