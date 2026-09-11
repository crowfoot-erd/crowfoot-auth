package net.java21.crowfoot.auth.client.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * core 인증 이벤트 감사 기록 요청 (08-core/05-account.md Section 3.5) — 기록은 best-effort.
 * detail은 core가 {"raw": ...}로 감싸 저장한다.
 */
public record CreateAuditLogRequest(
        String actorId,
        @NotBlank String action,
        String detail
) {
}
