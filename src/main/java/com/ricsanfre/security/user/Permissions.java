package com.ricsanfre.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permissions {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),
    MANAGER_CREATE("management:create"),
    MANAGER_DELETE("management:delete"),
    MANAGER_READ("management:read"),
    MANAGER_UPDATE("management:update"),
    ;
    @Getter
    private final String permission;
}
