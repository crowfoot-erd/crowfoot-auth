package net.java21.crowfoot.auth.client.dto;

import java.time.Instant;

/**
 * core 내부 검증 응답 (08-core/18-access-token.md Section 3.4).
 * 유효하지 않으면 active만 false로 온다 — 사유(없음·폐기·만료)는 구분해 오지 않는다.
 */
public record VerifyAccessTokenResponse(boolean active, String userId, String workspaceId, String tokenId, Instant expiresAt) {
}
