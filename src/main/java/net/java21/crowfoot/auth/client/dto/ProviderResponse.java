package net.java21.crowfoot.auth.client.dto;

/**
 * 활성 제공자 응답 — core internal DTO 미러 (08-core/05-account.md Section 1.2).
 */
public record ProviderResponse(String code, String displayName) {
}
