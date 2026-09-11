package net.java21.crowfoot.auth.client.dto;

/**
 * core 사용자 확보 응답 — userId는 숫자 문자열(core 계약: BIGINT 식별자는 문자열).
 */
public record GetOrCreateUserResponse(String userId, boolean created, boolean admin) {
}
