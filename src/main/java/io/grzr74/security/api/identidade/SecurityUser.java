package io.grzr74.security.api.identidade;

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
 * <p> E usado nos fluxos de autenticação para emitirPares tokens e, após a validação de um
 * access token, pelo filtro JWT como o principal da {@code Authentication} armazenada
 * no contexto de segurança. Assim, regras de autorização acessam a identidade e as
 * permissões da requisição sem consultar o serviço de usuários ou o Redis.</p>
 *
 */
public class SecurityUser implements UserDetails {


    /** Identificador de usuário do aplicativo. */
    private final String userId;

    /** O e-mail do usuário foi utilizado como nome de usuário do Spring Security. */
    private final String email;

    /**
     * Senha criptografada com Argon2. Obrigatória para login com e-mail/senha.
     * * Pode ser {@code null} para usuários que não possuem senha.
     */
    private final String password;

    /** Os nomes das permissões estão associados às autoridades que as concederam. */
    private final List<String> permissions;

    /** Retorna as autorizações derivadas de {@code permissions}. */
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
     * Retorna a senha criptografada com BCrypt para login baseado em credenciais.
     * * Preencha este campo ao criar um {@link SecurityUser} para autenticação por
     * e-mail/senha.
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Retorna o e-mail como nome principal.
     */
    @Override
    public String getUsername() {
        return email;
    }

}
