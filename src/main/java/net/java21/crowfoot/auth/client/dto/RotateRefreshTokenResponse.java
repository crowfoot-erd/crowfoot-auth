package net.java21.crowfoot.auth.client.dto;

/**
 * core Refresh Rotation 판정 결과 — verdict: ROTATED(정상) / GRACE(유예 내 재사용·멀티탭).
 * GRACE의 latestJti는 lineage 최신 jti(core 계약).
 */
public record RotateRefreshTokenResponse(String verdict, String latestJti) {
}
