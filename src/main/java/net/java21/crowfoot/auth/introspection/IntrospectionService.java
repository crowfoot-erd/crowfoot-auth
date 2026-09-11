package net.java21.crowfoot.auth.introspection;

import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.token.jwt.AccessTokenValidator;
import net.java21.crowfoot.auth.token.jwt.InactiveReason;
import net.java21.crowfoot.auth.token.jwt.JwtIssuer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;


/**
 * 토큰 검증 4항목 (02-auth/requirements.md Section 1.4.8) — 서명·exp(스큐)·iss·aud·typ=ACCESS는
 * {@link AccessTokenValidator}가, 블랙리스트(jti·sid MGET 1회)는 {@link BlacklistStore}가 담당.
 * Refresh 토큰은 INVALID로 거부된다(typ 검증). 검증 사유는 대분류만 노출한다.
 */
@Service
public class IntrospectionService {

    private final AccessTokenValidator accessTokenValidator;
    private final BlacklistStore blacklistStore;

    public IntrospectionService(AccessTokenValidator accessTokenValidator, BlacklistStore blacklistStore) {
        this.accessTokenValidator = accessTokenValidator;
        this.blacklistStore = blacklistStore;
    }

    public IntrospectionResponse introspect(String token) {
        AccessTokenValidator.TokenCheck check = accessTokenValidator.check(token);
        if (!check.active()) {
            return inactive(check.inactiveReason());
        }
        Jwt jwt = check.jwt();
        BlacklistStore.BlockResult blocked = blacklistStore.findBlocked(jwt.getId(),
                jwt.getClaimAsString("sid"));
        if (blocked.blocked()) {
            return inactive(InactiveReason.REVOKED);
        }
        return new IntrospectionResponse(
                true,
                jwt.getSubject(),
                jwt.getId(),
                jwt.getClaimAsString("sid"),
                jwt.getClaimAsString("typ"),
                // Security 7 — getIssuer() 반환형이 String에서 URL로 변경됨
                jwt.getIssuer().toString(),
                String.join(" ", jwt.getAudience()),
                jwt.getIssuedAt().toEpochMilli() / 1000,
                jwt.getExpiresAt().toEpochMilli() / 1000,
                null);
    }

    private IntrospectionResponse inactive(InactiveReason reason) {
        return new IntrospectionResponse(false, null, null, null, null, null, null, null, null,
                reason.name());
    }
}
