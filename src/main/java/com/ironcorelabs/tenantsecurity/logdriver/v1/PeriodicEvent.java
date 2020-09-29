package com.ironcorelabs.tenantsecurity.logdriver.v1;

public enum PeriodicEvent implements SecurityEvent {
    RETENTION_POLICY_ENFORCED,
    BACKUP_CREATED;

    public String getFlatEvent() {
        return "PERIODIC_" + this.name();
    }
}
