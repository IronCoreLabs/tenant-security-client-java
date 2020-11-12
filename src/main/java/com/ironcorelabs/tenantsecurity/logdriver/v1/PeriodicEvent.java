package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum PeriodicEvent implements SecurityEvent {
    ENFORCE_RETENTION_POLICY,
    CREATE_BACKUP;

    public String getFlatEvent() {
        return "PERIODIC_" + this.name();
    }
}
