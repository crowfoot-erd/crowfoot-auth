package net.java21.crowfoot.auth.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.config.AuthProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * auth_flow 쿠키 — 로그인 흐름 상태를 서명해 브라우저에 보관한다 (무상태, requirements Section 1.4.6).
 * 값은 Base64URL(payload JSON) + "." + Base64URL(HMAC-SHA256(payload)). 변조되면 서명 불일치로 버린다.
 * (Framework 7 — SameSite enum 폐지, 문자열 사용)
 * Path=/api/v1/auth·HttpOnly·SameSite=Lax(GitHub → 프론트 콜백은 cross-site 최상위 이동)·TTL 10분.
 */
@Component
public class AuthFlowCookieService {

    public static final String COOKIE_NAME = "auth_flow";
    private static final Duration TTL = Duration.ofMinutes(10);

    private final SecretKey flowSecretKey;
    private final AuthProperties properties;
    private final ObjectMapper objectMapper;

    public AuthFlowCookieService(SecretKey flowSecretKey, AuthProperties properties, ObjectMapper objectMapper) {
        this.flowSecretKey = flowSecretKey;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public void write(HttpServletResponse response, AuthFlowState state) {
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(state).getBytes(StandardCharsets.UTF_8));
        String cookieValue = payload + "." + sign(payload);
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, cookieValue)
                .path("/api/v1/auth")
                .httpOnly(true)
                .secure(properties.cookie().secure())
                .sameSite("Lax")
                .maxAge(TTL)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public Optional<AuthFlowState> read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                return decode(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    public void clear(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, "")
                .path("/api/v1/auth")
                .httpOnly(true)
                .secure(properties.cookie().secure())
                .sameSite("Lax")
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private Optional<AuthFlowState> decode(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        int separator = raw.lastIndexOf('.');
        if (separator <= 0) {
            return Optional.empty();
        }
        String payload = raw.substring(0, separator);
        String signature = raw.substring(separator + 1);
        if (!MessageDigest.isEqual(sign(payload).getBytes(StandardCharsets.US_ASCII),
                signature.getBytes(StandardCharsets.US_ASCII))) {
            return Optional.empty();
        }
        try {
            byte[] json = Base64.getUrlDecoder().decode(payload);
            return Optional.of(objectMapper.readValue(json, AuthFlowState.class));
        } catch (IllegalArgumentException | JacksonException e) {
            return Optional.empty();
        }
    }

    private String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(flowSecretKey);
            byte[] digest = mac.doFinal(payload.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("auth_flow 서명 실패", e);
        }
    }
}
