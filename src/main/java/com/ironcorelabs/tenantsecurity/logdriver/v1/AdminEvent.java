package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum AdminEvent implements SecurityEvent {
  ADD, REMOVE, CHANGE_PERMISSIONS, CHANGE_SETTING;

  public String getFlatEvent() {
    return "ADMIN_" + this.name();
  }
}
