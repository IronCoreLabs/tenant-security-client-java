package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum DataEvent implements SecurityEvent {
  IMPORT, EXPORT, ENCRYPT, DECRYPT, CREATE, DELETE, DENY_ACCESS, CHANGE_PERMISSIONS;

  public String getFlatEvent() {
    return "DATA_" + this.name();
  }
}
