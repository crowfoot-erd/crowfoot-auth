package net.java21.crowfoot.auth.token.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.token.RefreshCookieWriter;
import net.java21.crowfoot.auth.token.jwt.AccessTokenValidator;
import net.java21.crowfoot.auth.token.jwt.RefreshTokenParser;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;

/**
 * 로그아웃 (02-auth/api.md Section 3.4) — 쿠키가 없어도 멱등 200(응답 본문 없음).
 * ① Refresh: 서명·typ 검증(만료는 허용) 후 core DELETE(jti) — 폐기 실패는 503 전파(fail-closed),
 *    무효 서명·typ는 조용히 스킵(폐기할 자격증명이 아니다).
 * ② Bearer Access: 유효할 때만 bl:at:{jti} 등록(TTL=잔여 수명) — 만료·무효는 등록하지 않는다.
 * ③ crowfoot_refresh 쿠키 삭제.
 */
@Service
public class LogoutService {

    public static final String ACTION_USER_LOGGED_OUT = "USER_LOGGED_OUT";
    private static final String BLACKLIST_REASON_LOGOUT = "LOGOUT";

    private final RefreshTokenParser refreshTokenParser;
    private final AccessTokenValidator accessTokenValidator;
    private final CoreClient coreClient;
    private final BlacklistStore blacklistStore;
    private final RefreshCookieWriter refreshCookieWriter;
    private final Clock clock;

    public LogoutService(RefreshTokenParser refreshTokenParser,
                         AccessTokenValidator accessTokenValidator,
                         CoreClient coreClient,
                         BlacklistStore blacklistStore,
                         RefreshCookieWriter refreshCookieWriter,
                         Clock clock) {
        this.refreshTokenParser = refreshTokenParser;
        this.accessTokenValidator = accessTokenValidator;
        this.coreClient = coreClient;
        this.blacklistStore = blacklistStore;
        this.refreshCookieWriter = refreshCookieWriter;
        this.clock = clock;
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        revokeRefreshToken(request);
        blacklistAccessToken(request);
        refreshCookieWriter.clear(response);
    }

    private void revokeRefreshToken(HttpServletRequest request) {
        String token = refreshCookieWriter.read(request).orElse(null);
        if (token == null) {
            return;
        }
        long userId;
        String jti;
        try {
            RefreshTokenParser.RefreshClaims claims = refreshTokenParser.parseLeniently(token);
            userId = Long.parseLong(claims.sub());
            jti = claims.jti();
        } catch (BusinessException e) {
            if (ErrorCode.AUTH_TOKEN_INVALID.equals(e.getErrorCode())) {
                return; // 무효한 Refresh — 폐기할 게 없다(멱등 진행)
            }
            throw e;
        }
        coreClient.revokeRefreshToken(jti);
        coreClient.recordAuditLog(userId, ACTION_USER_LOGGED_OUT, "reason=logout");
    }

    private void blacklistAccessToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return;
        }
        AccessTokenValidator.TokenCheck check = accessTokenValidator.check(authorization.substring(7));
        if (!check.active()) {
            return; // 만료(EXPIRED)·무효(INVALID) — 블랙리스트가 필요 없다
        }
        Duration remaining = Duration.between(clock.instant(), check.jwt().getExpiresAt());
        if (!remaining.isNegative() && !remaining.isZero()) {
            blacklistStore.registerAccessToken(check.jwt().getId(), BLACKLIST_REASON_LOGOUT, remaining);
        }
    }
}
