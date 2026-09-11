package net.java21.crowfoot.auth.oauth2.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * OAuth 인가 코드 교환 요청 (02-auth/api.md Section 3.2) — 콜백 페이지가 code·state를 받아 이 API로 넘긴다.
 *
 * @param code  제공자가 콜백 URL에 실은 인가 코드(일회성)
 * @param state 콜백 URL의 state — auth_flow 쿠키의 state와 대조된다
 */
public record TokenExchangeRequest(
        @NotBlank String code,
        @NotBlank String state
) {
}
