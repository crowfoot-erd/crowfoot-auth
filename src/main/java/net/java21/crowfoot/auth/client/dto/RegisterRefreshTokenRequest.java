package net.java21.crowfoot.auth.client.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

/**
 * core Refresh 저장소 등록(발급) 요청 (08-core/05-account.md Section 3.2).
 * jti·sid는 UUID 문자열, expiresAt은 Instant ISO-8601 — core 계약 준수.
 */
public record RegisterRefreshTokenRequest(
        @NotBlank String userId,
        @NotBlank String jti,
        @NotBlank String sid,
        @NotNull Instant expiresAt,
        String ip,
        String userAgent
) {
}
