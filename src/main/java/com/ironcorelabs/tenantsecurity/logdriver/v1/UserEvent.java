package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum UserEvent implements SecurityEvent {
    ADD,
    SUSPEND,
    REMOVE,
    LOGIN,
    SESSION_TIMEOUT,
    LOCKOUT,
    LOGOUT,
    CHANGE_PERMISSIONS,
    PASSWORD_EXPIRED,
    PASSWORD_RESET,
    PASSWORD_CHANGE,
    BAD_LOGIN,
    ENABLE_TWO_FACTOR,
    DISABLE_TWO_FACTOR,
    EMAIL_CHANGE,
    EMAIL_VERIFICATION_REQUESTED,
    EMAIL_VERIFIED;

    public String getFlatEvent() {
        return "USER_" + this.name();
    }
}
