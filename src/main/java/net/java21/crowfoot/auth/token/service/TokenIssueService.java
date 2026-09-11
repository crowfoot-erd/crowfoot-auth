package net.java21.crowfoot.auth.token.service;

import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
import net.java21.crowfoot.auth.token.jwt.JwtIssuer;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * 로그인 완료 시점의 토큰 발급 — sid 생성 → Access+Refresh 발급 → core Refresh 등록 → 감사.
 * core 등록 실패 시 예외가 그대로 전파돼 로그인 전체가 실패한다(부분 성공 토큰 방지, fail-closed).
 */
@Service
public class TokenIssueService {

    public static final String ACTION_USER_LOGGED_IN = "USER_LOGGED_IN";

    private final JwtIssuer jwtIssuer;
    private final CoreClient coreClient;

    public TokenIssueService(JwtIssuer jwtIssuer, CoreClient coreClient) {
        this.jwtIssuer = jwtIssuer;
        this.coreClient = coreClient;
    }

    /**
     * @param userId  core가 확보한 회원 식별자(숫자 문자열 → BIGINT)
     * @param provider 제공자 코드(감사 상세)
     */
    public IssuedTokens issueForLogin(String userId, String provider, String ip, String userAgent) {
        long userIdNumeric = Long.parseLong(userId);
        String sid = UUID.randomUUID().toString();
        IssuedToken accessToken = jwtIssuer.issueAccessToken(userId, sid);
        IssuedToken refreshToken = jwtIssuer.issueRefreshToken(userId, sid);
        coreClient.registerRefreshToken(userIdNumeric, refreshToken.jti(), sid, refreshToken.expiresAt(), ip, userAgent);
        coreClient.recordAuditLog(userIdNumeric, ACTION_USER_LOGGED_IN, "provider=" + provider);
        return new IssuedTokens(sid, accessToken, refreshToken);
    }

    /**
     * 로그인 한 건의 발급 결과 — sid는 Access·Refresh가 공유하는 세션 식별자(블랙리스트 bl:sid:{sid} 키).
     */
    public record IssuedTokens(String sid, IssuedToken accessToken, IssuedToken refreshToken) {
    }
}
