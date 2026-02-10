package org.skystream.authapp.domain.event;

import lombok.Getter;
import org.skystream.authapp.domain.entity.UserEntity;
import org.springframework.context.ApplicationEvent;

@Getter
public class UserRegisteredEvent extends ApplicationEvent {

    private final UserEntity user;
    private final String verificationToken;

    public UserRegisteredEvent(Object source, UserEntity user, String verificationToken) {
        super(source);
        this.user = user;
        this.verificationToken = verificationToken;
    }
}