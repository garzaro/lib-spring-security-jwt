package io.grzr74.security.permission;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Restringe o acesso a uma classe ou metodo com base em uma permissão necessária.
 */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAuthority('{value}')")
public @interface HasPermission {

    /**
     * Nome da permissão necessária.
     * Este valor deve corresponder a uma entrada na declaração (claim) {@code permissions} do JWT.
     */
    String value();

}
