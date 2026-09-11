package net.java21.crowfoot.auth.blacklist;

import java.time.Duration;

/**
 * Access 토큰·세션 블랙리스트 저장소 계약 (02-auth/requirements.md Section 1.4.7).
 * 키: bl:at:{jti}(값=사유 LOGOUT/REVOKED, TTL=토큰 잔여 수명)·bl:sid:{sid}(값=REVOKED, TTL=access-ttl).
 * 조회는 jti·sid 두 키를 1회 질의(MGET)로 묶는다.
 *
 * <p>계약: 저장소 접근 불가 시 SERVICE_UNAVAILABLE {@code BusinessException} — introspection은
 * fail-closed(503)로 막히고, 내부 폐기 API는 503을 그대로 내보낸다.
 */
public interface BlacklistStore {

    void registerAccessToken(String jti, String reason, Duration ttl);

    void registerSession(String sid, Duration ttl);

    BlockResult findBlocked(String jti, String sid);

    /** jti·sid 각각의 차단 여부 — 세션 차단이면 jti 무관 전부 차단 */
    record BlockResult(boolean tokenBlocked, boolean sessionBlocked) {

        public boolean blocked() {
            return tokenBlocked || sessionBlocked;
        }
    }
}
