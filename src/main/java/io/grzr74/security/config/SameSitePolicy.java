package io.grzr74.security.config;

/**
 * SameSite policy applied to the authentication cookies.
 */
public enum SameSitePolicy {

    /**
     * Cookie is sent only to same-site requests.
     */
    STRICT("Strict"),

    /**
     * Cookie is sent on same-site requests and top-level cross-site navigation.
     */
    LAX("Lax"),

    /**
     * Cookie is sent on every request and requires {@code Secure}.
     */
    NONE("None");

    /**
     * Value written in the {@code SameSite} cookie attribute.
     */
    private final String attributeValue;

    /**
     * Creates a policy with its cookie attribute value.
     *
     * @param attributeValue value written to the browser
     */
    SameSitePolicy(final String attributeValue) {
        this.attributeValue = attributeValue;
    }

    /**
     * Returns the value written in the {@code SameSite} cookie attribute.
     *
     * @return attribute value
     */
    public String attributeValue() {
        return attributeValue;
    }
}
