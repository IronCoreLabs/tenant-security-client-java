package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum UserEvent implements SecurityEvent {
  ADD,
  SUSPEND,
  REMOVE,
  LOGIN,
  TIMEOUT_SESSION,
  LOCKOUT,
  LOGOUT,
  CHANGE_PERMISSIONS,
  EXPIRE_PASSWORD,
  RESET_PASSWORD,
  CHANGE_PASSWORD,
  REJECT_LOGIN,
  ENABLE_TWO_FACTOR,
  DISABLE_TWO_FACTOR,
  CHANGE_EMAIL,
  REQUEST_EMAIL_VERIFICATION,
  VERIFY_EMAIL;

  public String getFlatEvent() {
    return "USER_" + this.name();
  }
}
