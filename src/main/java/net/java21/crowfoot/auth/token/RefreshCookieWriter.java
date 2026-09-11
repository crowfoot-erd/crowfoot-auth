package net.java21.crowfoot.auth.token;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.config.AuthProperties;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * crowfoot_refresh 쿠키 — Refresh 토큰 전달 채널 (02-auth/requirements.md Section 1.4.6).
 * Path=/api/v1/auth·HttpOnly·Secure(프로필)·SameSite=Strict·Max-Age=refresh-ttl.
 * Path는 브라우저가 보는 외부 경로 기준(gateway StripPrefix 이전)이라 /api/v1/auth로 둔다.
 */
@Component
public class RefreshCookieWriter {

    public static final String COOKIE_NAME = "crowfoot_refresh";
    private static final String COOKIE_PATH = "/api/v1/auth";

    private final AuthProperties properties;

    public RefreshCookieWriter(AuthProperties properties) {
        this.properties = properties;
    }

    /** 쿠키에서 Refresh 토큰 회수 — 재발급·로그아웃의 유일한 자격증명 경로 */
    public Optional<String> read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    public void write(HttpServletResponse response, IssuedToken refreshToken) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, refreshToken.value())
                .path(COOKIE_PATH)
                .httpOnly(true)
                .secure(properties.cookie().secure())
                .sameSite("Strict")
                .maxAge(properties.token().refreshTtl())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void clear(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, "")
                .path(COOKIE_PATH)
                .httpOnly(true)
                .secure(properties.cookie().secure())
                .sameSite("Strict")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
