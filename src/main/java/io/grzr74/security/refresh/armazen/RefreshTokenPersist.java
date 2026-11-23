package io.grzr74.security.refresh.armazen;

import io.grzr74.security.refresh.enums.RotationStatus;
import io.grzr74.security.refresh.model.RefreshToken;
import io.grzr74.security.refresh.model.RotationResult;

import java.time.Duration;

/** Port
 * Interface para persistência de tokens de atualização (*refresh tokens*).
 * As implementações devem realizar a rotação de forma atômica, de modo
 * que um token possa ser consumido apenas uma vez.
 */
public interface RefreshTokenPersist {

    /**
     * Persists a new token and its family, creating the session.
     *
     * @param token token record to store
     * @param ttl   family lifetime measured from now
     */
    void gerarRefreshToken(RefreshToken token, Duration ttl);

    /**
     * Validates, consumes, and replaces a token in one atomic operation.
     * A reused token revokes the whole family before returning {@link RotationStatus#REUTILIZADO}.
     *
     * @param tokenHashAtual SHA-256 hash of the presented secret
     * @param proximoTokenHash    SHA-256 hash of the replacement secret
     * @return rotation outcome and identity when rotated
     */
    RotationResult rotacionar(String tokenHashAtual, String proximoTokenHash);

    /**
     * Revokes the family that owns the given token, if it still exists.
     *
     * @param tokenHash SHA-256 hash of the presented secret
     */
    void revogarFamilia(String tokenHash);

    /**
     * Revokes every family issued to the given user.
     *
     * @param usuarioId user identifier
     */
    void revogaAllByUsuarioId(String usuarioId);

}
