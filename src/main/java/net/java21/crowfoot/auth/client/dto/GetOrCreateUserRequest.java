package net.java21.crowfoot.auth.client.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * core 사용자 확보(get-or-create) 요청 — core internal DTO 미러 (08-core/05-account.md Section 3.1).
 * OAuth2 제공자 신원(provider·providerUserId)으로 회원을 확보한다.
 */
public record GetOrCreateUserRequest(
        @NotBlank String provider,
        @NotBlank String providerUserId,
        String email,
        @NotBlank String name
) {
}
