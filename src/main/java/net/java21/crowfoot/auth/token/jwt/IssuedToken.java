package net.java21.crowfoot.auth.token.jwt;

import java.time.Instant;

/**
 * 발급된 토큰 1건 — jti(UUID v4)는 발급마다 상이하다 (02-auth/requirements.md Section 1.4.2).
 *
 * @param value     직렬화된 JWT
 * @param jti       토큰 식별자(블랙리스트·Refresh 저장소 키)
 * @param expiresAt 만료 시각
 */
public record IssuedToken(String value, String jti, Instant expiresAt) {
}
