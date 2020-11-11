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
        assertEquals(DataEvent.ACCESS_DENIED.getFlatEvent(), "DATA_ACCESS_DENIED");
        assertEquals(DataEvent.CHANGE_PERMISSIONS.getFlatEvent(), "DATA_CHANGE_PERMISSIONS");

        // PERIODIC
        assertEquals(PeriodicEvent.RETENTION_POLICY_ENFORCED.getFlatEvent(),
                "PERIODIC_RETENTION_POLICY_ENFORCED");
        assertEquals(PeriodicEvent.BACKUP_CREATED.getFlatEvent(), "PERIODIC_BACKUP_CREATED");

        // USER
        assertEquals(UserEvent.ADD.getFlatEvent(), "USER_ADD");
        assertEquals(UserEvent.SUSPEND.getFlatEvent(), "USER_SUSPEND");
        assertEquals(UserEvent.REMOVE.getFlatEvent(), "USER_REMOVE");
        assertEquals(UserEvent.LOGIN.getFlatEvent(), "USER_LOGIN");
        assertEquals(UserEvent.SESSION_TIMEOUT.getFlatEvent(), "USER_SESSION_TIMEOUT");
        assertEquals(UserEvent.LOCKOUT.getFlatEvent(), "USER_LOCKOUT");
        assertEquals(UserEvent.LOGOUT.getFlatEvent(), "USER_LOGOUT");
        assertEquals(UserEvent.CHANGE_PERMISSIONS.getFlatEvent(), "USER_CHANGE_PERMISSIONS");
        assertEquals(UserEvent.PASSWORD_EXPIRED.getFlatEvent(), "USER_PASSWORD_EXPIRED");
        assertEquals(UserEvent.PASSWORD_RESET.getFlatEvent(), "USER_PASSWORD_RESET");
        assertEquals(UserEvent.PASSWORD_CHANGE.getFlatEvent(), "USER_PASSWORD_CHANGE");
        assertEquals(UserEvent.BAD_LOGIN.getFlatEvent(), "USER_BAD_LOGIN");
        assertEquals(UserEvent.ENABLE_TWO_FACTOR.getFlatEvent(), "USER_ENABLE_TWO_FACTOR");
        assertEquals(UserEvent.DISABLE_TWO_FACTOR.getFlatEvent(), "USER_DISABLE_TWO_FACTOR");
        assertEquals(UserEvent.EMAIL_CHANGE.getFlatEvent(), "USER_EMAIL_CHANGE");
        assertEquals(UserEvent.EMAIL_VERIFICATION_REQUESTED.getFlatEvent(),
                "USER_EMAIL_VERIFICATION_REQUESTED");
        assertEquals(UserEvent.EMAIL_VERIFIED.getFlatEvent(), "USER_EMAIL_VERIFIED");


    }
}
