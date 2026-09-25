package net.java21.crowfoot.auth.common.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * 인증 서버 에러 코드 (02-auth/api.md Section 5 + 01-architecture/api-design.md Section 5.4).
 *
 * <p>에러 원인 상세(어떤 조건이 실패했는지)는 응답에 구분해 노출하지 않는다.
 * AUTH_TOKEN_INVALID의 상태코드는 401로 통일한다 — auth에서 이 코드를 쓰는 재발급은
 * 토큰이 자격증명인 요청이다 (api.md Section 5 각주).
 */
@Getter
public enum ErrorCode {

    // 공통 (api-design.md Section 5.4)
    SUCCESS(HttpStatus.OK, "SUCCESS", "SUCCESS"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "요청 형식이 올바르지 않습니다"),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "리소스를 찾을 수 없습니다"),
    SERVICE_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "서비스를 일시적으로 사용할 수 없습니다"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "서버 내부 오류가 발생했습니다"),

    // 인증 서버 전용 (02-auth/api.md Section 5)
    AUTH_STATE_INVALID(HttpStatus.BAD_REQUEST, "AUTH_STATE_INVALID", "로그인 요청 정보가 유효하지 않습니다"),
    AUTH_PROVIDER_ERROR(HttpStatus.BAD_GATEWAY, "AUTH_PROVIDER_ERROR", "인증 제공자와의 통신에 실패했습니다"),
    AUTH_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "AUTH_TOKEN_INVALID", "토큰이 유효하지 않습니다"),
    AUTH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "AUTH_TOKEN_EXPIRED", "토큰이 만료되었습니다"),
    AUTH_SESSION_REVOKED(HttpStatus.UNAUTHORIZED, "AUTH_SESSION_REVOKED", "세션이 무효화되었습니다"),
    USER_WITHDRAWN(HttpStatus.CONFLICT, "USER_WITHDRAWN", "탈퇴한 계정입니다");

    private final HttpStatus status;
    private final String code;
    private final String defaultMessage;

    ErrorCode(HttpStatus status, String code, String defaultMessage) {
        this.status = status;
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    /** 번들 키 — i18n/messages_{ko,en,ja,zh}.properties의 error.{code} (api-design.md §5.7, core 미러) */
    public String messageKey() {
        return "error." + code.toLowerCase();
    }
}
