package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import com.ironcorelabs.tenantsecurity.logdriver.v1.AdminEvent;
import com.ironcorelabs.tenantsecurity.logdriver.v1.DataEvent;
import com.ironcorelabs.tenantsecurity.logdriver.v1.PeriodicEvent;
import com.ironcorelabs.tenantsecurity.logdriver.v1.UserEvent;
import org.testng.annotations.Test;

@Test(groups = {"unit"})
public class SecurityEventTest {
    public void interfaceConsistencyCheck() throws Exception {
        // ADMIN
        assertEquals(AdminEvent.ADD.getFlatEvent(), "ADMIN_ADD");
        assertEquals(AdminEvent.REMOVE.getFlatEvent(), "ADMIN_REMOVE");
        assertEquals(AdminEvent.CHANGE_PERMISSIONS.getFlatEvent(), "ADMIN_CHANGE_PERMISSIONS");
        assertEquals(AdminEvent.CHANGE_SETTING.getFlatEvent(), "ADMIN_CHANGE_SETTING");

        // DATA
        assertEquals(DataEvent.IMPORT.getFlatEvent(), "DATA_IMPORT");
        assertEquals(DataEvent.EXPORT.getFlatEvent(), "DATA_EXPORT");
        assertEquals(DataEvent.ENCRYPT.getFlatEvent(), "DATA_ENCRYPT");
        assertEquals(DataEvent.DECRYPT.getFlatEvent(), "DATA_DECRYPT");
        assertEquals(DataEvent.CREATE.getFlatEvent(), "DATA_CREATE");
        assertEquals(DataEvent.DELETE.getFlatEvent(), "DATA_DELETE");
        assertEquals(DataEvent.DENY_ACCESS.getFlatEvent(), "DATA_DENY_ACCESS");
        assertEquals(DataEvent.CHANGE_PERMISSIONS.getFlatEvent(), "DATA_CHANGE_PERMISSIONS");

        // PERIODIC
        assertEquals(PeriodicEvent.ENFORCE_RETENTION_POLICY.getFlatEvent(),
                "PERIODIC_ENFORCE_RETENTION_POLICY");
        assertEquals(PeriodicEvent.CREATE_BACKUP.getFlatEvent(), "PERIODIC_CREATE_BACKUP");

        // USER
        assertEquals(UserEvent.ADD.getFlatEvent(), "USER_ADD");
        assertEquals(UserEvent.SUSPEND.getFlatEvent(), "USER_SUSPEND");
        assertEquals(UserEvent.REMOVE.getFlatEvent(), "USER_REMOVE");
        assertEquals(UserEvent.LOGIN.getFlatEvent(), "USER_LOGIN");
        assertEquals(UserEvent.TIMEOUT_SESSION.getFlatEvent(), "USER_TIMEOUT_SESSION");
        assertEquals(UserEvent.LOCKOUT.getFlatEvent(), "USER_LOCKOUT");
        assertEquals(UserEvent.LOGOUT.getFlatEvent(), "USER_LOGOUT");
        assertEquals(UserEvent.CHANGE_PERMISSIONS.getFlatEvent(), "USER_CHANGE_PERMISSIONS");
        assertEquals(UserEvent.EXPIRE_PASSWORD.getFlatEvent(), "USER_EXPIRE_PASSWORD");
        assertEquals(UserEvent.RESET_PASSWORD.getFlatEvent(), "USER_RESET_PASSWORD");
        assertEquals(UserEvent.CHANGE_PASSWORD.getFlatEvent(), "USER_CHANGE_PASSWORD");
        assertEquals(UserEvent.REJECT_LOGIN.getFlatEvent(), "USER_REJECT_LOGIN");
        assertEquals(UserEvent.ENABLE_TWO_FACTOR.getFlatEvent(), "USER_ENABLE_TWO_FACTOR");
        assertEquals(UserEvent.DISABLE_TWO_FACTOR.getFlatEvent(), "USER_DISABLE_TWO_FACTOR");
        assertEquals(UserEvent.CHANGE_EMAIL.getFlatEvent(), "USER_CHANGE_EMAIL");
        assertEquals(UserEvent.REQUEST_EMAIL_VERIFICATION.getFlatEvent(),
                "USER_REQUEST_EMAIL_VERIFICATION");
        assertEquals(UserEvent.VERIFY_EMAIL.getFlatEvent(), "USER_VERIFY_EMAIL");


    }
}
