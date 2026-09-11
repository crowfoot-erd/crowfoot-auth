package net.java21.crowfoot.auth.client;

import lombok.Getter;

/**
 * core가 도메인 결과(4xx)로 응답한 경우 — core가 보낸 resultCode를 그대로 담는다.
 * 호출 서비스가 verdict별(auth 계약)로 변환한다 (예: REFRESH_TOKEN_NOT_FOUND → AUTH_TOKEN_INVALID).
 */
@Getter
public class CoreCallException extends RuntimeException {

    private final String resultCode;

    public CoreCallException(String resultCode, String message) {
        super(message);
        this.resultCode = resultCode;
    }
}
