package net.java21.crowfoot.auth.client;

import net.java21.crowfoot.auth.client.dto.GetOrCreateUserResponse;
import net.java21.crowfoot.auth.client.dto.ProviderResponse;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenResponse;

import java.time.Instant;
import java.util.List;

/**
 * core 내부 API 호출의 서비스 facing 인터페이스 — 요청 조립·응답 해석·에러 매핑은 {@link CoreClientImpl}.
 *
 * <p>에러 계약: core 4xx 도메인 결과는 {@link CoreCallException}(resultCode 전파),
 * core 장애(5xx·타임아웃·연결 거부)는 SERVICE_UNAVAILABLE {@code BusinessException}으로 변환한다.
 * 감사 기록은 best-effort — 실패해도 예외를 던지지 않는다.
 */
public interface CoreClient {

    /** OAuth2 제공자 신원으로 회원 확보 — 탈퇴 계정은 CoreCallException(USER_WITHDRAWN) */
    GetOrCreateUserResponse getOrCreateUser(String provider, String providerUserId, String email, String name);

    /** Refresh 발급 등록 — jti 중복은 core가 조용히 멱등 처리(201) */
    void registerRefreshToken(long userId, String jti, String sid, Instant expiresAt, String ip, String userAgent);

    /** Refresh Rotation 판정 — verdict ROTATED/GRACE, 미지원 jti는 CoreCallException(REFRESH_TOKEN_NOT_FOUND),
     *  재사용 감지는 CoreCallException(AUTH_SESSION_REVOKED) */
    RotateRefreshTokenResponse rotateRefreshToken(long userId, String currentJti, String newJti, Instant newExpiresAt);

    /** Refresh 1건 폐기 — 멱등(없는 jti도 204) */
    void revokeRefreshToken(String jti);

    /** 세션(Refresh lineage) 폐기 — 멱등 */
    void revokeSession(String sid);

    /** 인증 이벤트 감사 기록 — best-effort, 실패 시 경고 로그만 */
    void recordAuditLog(long actorId, String action, String detail);

    /** 활성 제공자 목록(로그인 시작·교환의 활성 검증) */
    List<ProviderResponse> activeProviders();
}
