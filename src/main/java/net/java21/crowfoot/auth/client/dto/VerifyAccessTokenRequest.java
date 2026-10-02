package net.java21.crowfoot.auth.client.dto;

/** core 내부 검증 요청 — 워크스페이스 액세스 토큰 원문의 SHA-256(16진수) (08-core/18-access-token.md Section 3.4) */
public record VerifyAccessTokenRequest(String tokenHash) {
}
