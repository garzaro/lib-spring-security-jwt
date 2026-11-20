package io.grzr74.security.config.enums;

/**
 * A política SameSite aplicada aos cookies de autenticação.
 */
public enum SameSitePolicy {

    /**
     * O cookie é enviado apenas para solicitações do mesmo site.
     */
    STRICT("Strict"),

    /**
     * Os cookies são enviados em solicitações dentro do mesmo
     * site e na navegação entre sites de nível superior.
     */
    LAX("Lax"),

    /**
     * Um cookie é enviado em cada solicitação e requer {@code Secure}.
     */
    NONE("None");

    /**
     * Valor escrito no atributo de cookie {@code SameSite}.
     */
    private final String attributeValue;

    /**
     * Cria uma política com o valor do atributo de cookie.
     * @param attributeValue valor gravado no navegador
     */
    SameSitePolicy(final String attributeValue) {
        this.attributeValue = attributeValue;
    }

    /**
     * Retorna o valor escrito no atributo do cookie {@code SameSite}.
     * @return valor do atributo
     */
    public String attributeValue() {
        return attributeValue;
    }
}
