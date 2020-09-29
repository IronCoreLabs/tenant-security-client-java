package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum DataEvent implements SecurityEvent {
    IMPORT,
    EXPORT,
    ENCRYPT, 
    DECRYPT,
    CREATE,
    DELETE,
    ACCESS_DENIED,
    CHANGE_PERMISSIONS;

    public String getFlatEvent() {
        return "DATA_" + this.name();
    }
}
