package net.java21.crowfoot.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 인증 서버 정책값 (02-auth/requirements.md Section 1.4.4) — 파생값(쿠키 Max-Age·블랙리스트 TTL)은
 * 별도 키 없이 이 값들로 계산한다. 시크릿(jwt-secret·flow-secret)은 환경변수에서만 공급된다.
 *
 * @param token      토큰 정책(TTL·유예·스큐·iss·aud)
 * @param front      브라우저가 보는 프론트 오리진 — OAuth 콜백(redirect_uri) 조립 기점
 * @param cookie     쿠키 Secure 플래그(이름은 계약 고정: crowfoot_refresh·auth_flow)
 * @param blacklist  블랙리스트 저장소 선택(redis | memory)
 * @param jwtSecret  JWT HS256 서명 키(Base64 32바이트 이상)
 * @param flowSecret auth_flow 쿠키 HMAC-SHA256 서명 키(Base64 32바이트 이상, 용도 분리)
 */
@ConfigurationProperties("crowfoot.auth")
public record AuthProperties(
        Token token,
        Front front,
        Cookie cookie,
        Blacklist blacklist,
        String jwtSecret,
        String flowSecret
) {

    public AuthProperties {
        Objects.requireNonNull(token, "crowfoot.auth.token 은 필수");
        Objects.requireNonNull(front, "crowfoot.auth.front 는 필수");
        Objects.requireNonNull(cookie, "crowfoot.auth.cookie 는 필수");
        Objects.requireNonNull(blacklist, "crowfoot.auth.blacklist 은 필수");
        if (token.accessTtl() == null || token.accessTtl().isNegative() || token.accessTtl().isZero()) {
            throw new IllegalArgumentException("crowfoot.auth.token.access-ttl 은 양수여야 한다");
        }
        if (token.refreshTtl() == null || token.refreshTtl().isNegative() || token.refreshTtl().isZero()) {
            throw new IllegalArgumentException("crowfoot.auth.token.refresh-ttl 은 양수여야 한다");
        }
        if (token.issuer() == null || token.issuer().isBlank()) {
            throw new IllegalArgumentException("crowfoot.auth.token.issuer 는 필수");
        }
        if (token.audience() == null || token.audience().isEmpty()) {
            throw new IllegalArgumentException("crowfoot.auth.token.audience 은 1개 이상");
        }
        if (!"redis".equals(blacklist.store()) && !"memory".equals(blacklist.store())) {
            throw new IllegalArgumentException("crowfoot.auth.blacklist.store 은 redis | memory");
        }
    }

    /** 토큰 정책 — Access 60m / Refresh 6h(슬라이딩) / Rotation 유예 30s / 클럭 스큐 30s */
    public record Token(
            Duration accessTtl,
            Duration refreshTtl,
            Duration rotationGrace,
            Duration clockSkew,
            String issuer,
            List<String> audience
    ) {
    }

    /** 프론트 오리진 — GitHub 앱에 등록된 콜백과 동일한 값이 조립된다 */
    public record Front(String origin, String callbackPath) {

        /** OAuth 콜백(redirect_uri) — 예: http://localhost:8080/auth/callback */
        public String callbackUrl() {
            return origin + callbackPath;
        }
    }

    /** 쿠키 플래그 — 이름 crowfoot_refresh·auth_flow는 계약 고정이라 프로퍼티로 두지 않는다 */
    public record Cookie(boolean secure) {
    }

    /** 블랙리스트 저장소 — local은 방화벽 기간 memory 우회 */
    public record Blacklist(String store) {
    }
}
