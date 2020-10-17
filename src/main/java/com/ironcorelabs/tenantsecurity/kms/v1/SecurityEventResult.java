package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;

public class SecurityEventResult {
    @Key
    private boolean eventQueued;

    /**
     * Has the event been received and queued for further processing. Since Security Event logging is an
     * asynchronous operation at the TSP, a true value for isEventQueued does not mean that the
     * security event has been delivered or that the event is deliverable. It simply means that the event
     * has been received the by the TSP and will be processed.
     * @return true if the security event successfully accepted and enqueued for processing
     */
    public boolean isEventQueued() {
        return eventQueued;
    }
}
