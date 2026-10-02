package net.java21.crowfoot.auth.introspection;

import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.token.jwt.AccessTokenValidator;
import net.java21.crowfoot.auth.token.jwt.InactiveReason;
import net.java21.crowfoot.auth.token.jwt.JwtIssuer;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.VerifyAccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Service;


/**
 * 토큰 검증 4항목 (02-auth/api.md Section 4.1) — 서명·exp(스큐)·iss·aud·typ=ACCESS는
 * {@link AccessTokenValidator}가, 블랙리스트(jti·sid MGET 1회)는 {@link BlacklistStore}가 담당.
 * Refresh 토큰은 INVALID로 거부된다(typ 검증). 검증 사유는 대분류만 노출한다.
 */
@Service
public class IntrospectionService {

    /** 워크스페이스 액세스 토큰의 접두 — JWT와 구분한다 (08-core/18-access-token.md Section 2) */
    static final String WORKSPACE_TOKEN_PREFIX = "cfw_";
    static final String WORKSPACE_TOKEN_TYPE = "WORKSPACE_TOKEN";

    private final AccessTokenValidator accessTokenValidator;
    private final BlacklistStore blacklistStore;
    private final CoreClient coreClient;

    public IntrospectionService(AccessTokenValidator accessTokenValidator, BlacklistStore blacklistStore, CoreClient coreClient) {
        this.accessTokenValidator = accessTokenValidator;
        this.blacklistStore = blacklistStore;
        this.coreClient = coreClient;
    }

    public IntrospectionResponse introspect(String token) {
        if (token != null && token.startsWith(WORKSPACE_TOKEN_PREFIX)) {
            return introspectWorkspaceToken(token);
        }
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
                null,
                null,
                null);
    }

    /**
     * 워크스페이스 액세스 토큰 — JWT가 아니다. 원문의 SHA-256으로 core에 묻는다 (02-auth/api.md Section 4.1).
     * 폐기는 core 조회로 바로 반영되므로 블랙리스트를 보지 않는다. core가 응답하지 않으면 예외가 그대로 올라가
     * 503이 된다(fail-closed) — 통과시키지 않는다.
     */
    private IntrospectionResponse introspectWorkspaceToken(String token) {
        VerifyAccessTokenResponse verified = coreClient.verifyAccessToken(sha256(token));
        if (verified == null || !verified.active()) {
            // 없음·폐기·만료를 구분하지 않는다
            return inactive(InactiveReason.INVALID);
        }
        return new IntrospectionResponse(
                true,
                verified.userId(),
                null,
                null,
                WORKSPACE_TOKEN_TYPE,
                null,
                null,
                null,
                verified.expiresAt() == null ? null : verified.expiresAt().getEpochSecond(),
                null,
                verified.workspaceId(),
                verified.tokenId());
    }

    private static String sha256(String raw) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private IntrospectionResponse inactive(InactiveReason reason) {
        return new IntrospectionResponse(false, null, null, null, null, null, null, null, null,
                reason.name(), null, null);
    }
}
