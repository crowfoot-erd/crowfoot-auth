package net.java21.crowfoot.auth.token.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.client.CoreCallException;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.AuthProperties;
import net.java21.crowfoot.auth.token.RefreshCookieWriter;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
import net.java21.crowfoot.auth.token.jwt.JwtIssuer;
import net.java21.crowfoot.auth.token.jwt.RefreshTokenParser;
import org.springframework.stereotype.Service;

/**
 * 토큰 재발급 (02-auth/api.md Section 3.3) — 쿠키의 Refresh가 유일한 자격증명(Access 불필요).
 * core Rotation 판정: ROTATED→신규 jti Refresh·Access / GRACE(유예 30s 내 재사용·멀티탭)→lineage
 * 최신 jti를 승계 발급(core는 GRACE에서 행을 만들지 않는다 — jti 유지가 계약). sid는 그대로 승계한다.
 */
@Service
public class RefreshTokenService {

    public static final String VERDICT_ROTATED = "ROTATED";
    public static final String VERDICT_GRACE = "GRACE";
    public static final String ACTION_TOKEN_REFRESHED = "TOKEN_REFRESHED";

    private final RefreshTokenParser refreshTokenParser;
    private final JwtIssuer jwtIssuer;
    private final CoreClient coreClient;
    private final RefreshCookieWriter refreshCookieWriter;
    private final AuthProperties properties;

    public RefreshTokenService(RefreshTokenParser refreshTokenParser,
                               JwtIssuer jwtIssuer,
                               CoreClient coreClient,
                               RefreshCookieWriter refreshCookieWriter,
                               AuthProperties properties) {
        this.refreshTokenParser = refreshTokenParser;
        this.jwtIssuer = jwtIssuer;
        this.coreClient = coreClient;
        this.refreshCookieWriter = refreshCookieWriter;
        this.properties = properties;
    }

    public TokenResponse refresh(HttpServletRequest request, HttpServletResponse response) {
        String token = refreshCookieWriter.read(request)
                .orElseThrow(() -> new BusinessException(ErrorCode.AUTH_TOKEN_INVALID));
        RefreshTokenParser.RefreshClaims claims = refreshTokenParser.parse(token);

        // ROTATED 후보를 미리 발급(신규 jti)해 core에 심는다 — 승인 나면 이 토큰이 차기 Refresh
        IssuedToken candidate = jwtIssuer.issueRefreshToken(claims.sub(), claims.sid());
        RotateRefreshTokenResponse verdict = rotate(claims, candidate);

        IssuedToken nextRefresh;
        if (VERDICT_ROTATED.equals(verdict.verdict())) {
            nextRefresh = candidate;
        } else if (VERDICT_GRACE.equals(verdict.verdict())) {
            if (verdict.latestJti() == null || verdict.latestJti().isBlank()) {
                throw new BusinessException(ErrorCode.AUTH_TOKEN_INVALID);
            }
            nextRefresh = jwtIssuer.issueRefreshToken(claims.sub(), claims.sid(), verdict.latestJti());
        } else {
            throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE,
                    "알 수 없는 rotation verdict: " + verdict.verdict());
        }
        IssuedToken nextAccess = jwtIssuer.issueAccessToken(claims.sub(), claims.sid());

        refreshCookieWriter.write(response, nextRefresh);
        coreClient.recordAuditLog(Long.parseLong(claims.sub()), ACTION_TOKEN_REFRESHED,
                "verdict=" + verdict.verdict());
        return new TokenResponse(nextAccess.value(), TokenResponse.TOKEN_TYPE_BEARER,
                properties.token().accessTtl().toSeconds());
    }

    /** core rotate — 404 REFRESH_TOKEN_NOT_FOUND→AUTH_TOKEN_INVALID, 409 AUTH_SESSION_REVOKED→그대로, 그 외 도메인 4xx→503 */
    private RotateRefreshTokenResponse rotate(RefreshTokenParser.RefreshClaims claims, IssuedToken candidate) {
        try {
            return coreClient.rotateRefreshToken(Long.parseLong(claims.sub()), claims.jti(),
                    candidate.jti(), candidate.expiresAt());
        } catch (CoreCallException e) {
            if ("REFRESH_TOKEN_NOT_FOUND".equals(e.getResultCode())) {
                throw new BusinessException(ErrorCode.AUTH_TOKEN_INVALID);
            }
            if (ErrorCode.AUTH_SESSION_REVOKED.getCode().equals(e.getResultCode())) {
                throw new BusinessException(ErrorCode.AUTH_SESSION_REVOKED);
            }
            throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE, e.getMessage(), e);
        }
    }
}
