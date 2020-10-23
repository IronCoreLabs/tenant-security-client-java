package com.ironcorelabs.tenantsecurity.logdriver.v1;

public class CustomEvent implements SecurityEvent {
    String event;

    /**
     * Create a custom security event to be passed to a tenant's logging infrastructure.
     * 
     * @param eventName Name of the event. Must be in SCREAMING_SNAKE_CASE.
     */
    public CustomEvent(String eventName) {
        if (!eventName.matches("[A-Z_]+") || eventName.isEmpty() || eventName.charAt(0) == '_') {
            throw new IllegalArgumentException(
                    "Custom event must be screaming snake case, not empty, and start with a letter.");
        }
        this.event = eventName;
    }

    public String getFlatEvent() {
        return "CUSTOM_" + this.event;
    }
}
