package io.grzr74.security.permissoes;

import io.grzr74.security.api.identidade.SecurityUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

/**
 * Avalia se o usuário atual possui uma determinada permissão.
 * Utilizado por expressões de permissão do Spring Security.
 */
@Slf4j
@Qualifier("customPermissionEvaluator")
public class CustomPermissionEvaluator implements PermissionEvaluator {

    /**
     * Verifica se o usuário atual possui a permissão solicitada.
     *
     * @param authentication autenticação atual
     * @param targetDomainObject objeto de destino (não utilizado)
     * @param permission nome da permissão a ser verificada
     * @return {@code true} se concedida, caso contrário {@code false}
     */
    @Override
    public boolean hasPermission(final Authentication authentication,
                                 final Object targetDomainObject,
                                 final Object permission) {
        if (authentication == null || !(permission instanceof String permissionName)) {
            return false;
        }

        if (!(authentication.getPrincipal() instanceof SecurityUser securityUser)) {
            return false;
        }
        /**Verificação de permissão — usuário: {}, permissão: {}, concedida:**/
        boolean granted = securityUser.getPermissions().contains(permissionName);
        log.debug("Verificação de permissão: {}, permission: {}, granted: {}",
                securityUser.getEmail(), permissionName, granted);

        return granted;
    }

    /**
     * Verifica a permissão quando os valores de ID/tipo do alvo são fornecidos.
     *
     * * Delega para a verificação de permissão baseada em nome.
     *
     * @param authentication autenticação atual
     * @param targetId ID do objeto alvo (não utilizado)
     *
     * @param targetType Tipo do objeto alvo (não utilizado)
     * @param permission Nome da permissão a ser verificada
     * @return {@code true} se concedida, caso contrário {@code false}
     */
    @Override
    public boolean hasPermission(final Authentication authentication,
                                 final Serializable targetId,
                                 final String targetType,
                                 final Object permission) {
        return hasPermission(authentication, null, permission);
    }
}