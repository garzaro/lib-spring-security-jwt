package io.grzr74.security.user;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@Builder
/**
 * Representa o usuário da aplicação para o Spring Security, adaptando sua identidade,
 * credencial e permissões ao contrato {@link UserDetails}.
 *
 * <p>É usado nos fluxos de autenticação para emitir tokens e, após a validação de um
 * access token, pelo filtro JWT como o principal da {@code Authentication} armazenada
 * no contexto de segurança. Assim, regras de autorização acessam a identidade e as
 * permissões da requisição sem consultar o serviço de usuários ou o Redis.</p>
 */
public class SecurityUser implements UserDetails {


    /** Application user identifier. */
    private final String userId;

    /** User email used as the Spring Security username. */
    private final String email;

    /**
     * BCrypt-hashed password. Required for email/password login.
     * May be {@code null} for passwordless-only users.
     */
    private final String password;

    /** Permission names mapped to granted authorities. */
    private final List<String> permissions;

    /** Returns authorities derived from {@code permissions}. */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (permissions == null) {
            return List.of();
        }
        return permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    /**
     * Returns the BCrypt-hashed password for credential-based login.
     * Populate this field when building a {@link SecurityUser} for email/password auth.
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Returns the email as the principal name.
     */
    @Override
    public String getUsername() {
        return email;
    }

}
