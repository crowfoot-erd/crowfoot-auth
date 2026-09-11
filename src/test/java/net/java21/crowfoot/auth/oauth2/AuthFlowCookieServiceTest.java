package net.java21.crowfoot.auth.oauth2;

import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.ObjectMapper;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthFlowCookieServiceTest {

    private AuthFlowCookieService cookieService;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        cookieService = new AuthFlowCookieService(TestTokenFactory.secretKey(),
                TestAuthProperties.create(), new ObjectMapper());
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("auth_flow 쿠키 왕복 — write→read로 state·registrationId·redirectUri 복원, Set-Cookie 형식(Path·HttpOnly·Lax)")
    void writeAndReadRoundTrip() {
        AuthFlowState state = new AuthFlowState("state-abc", null, "github",
                "http://localhost:8080/auth/callback", Set.of("read:user", "user:email"));

        cookieService.write(response, state);
        String setCookie = response.getHeader("Set-Cookie");

        assertThat(setCookie).startsWith("auth_flow=");
        assertThat(setCookie).contains("Path=/api/v1/auth");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Lax");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("auth_flow", cookieValueOf(setCookie)));
        assertThat(cookieService.read(request)).hasValue(state);
    }

    @Test
    @DisplayName("payload 변조 — 서명 불일치로 버린다(empty)")
    void tamperedCookieRejected() {
        AuthFlowState state = new AuthFlowState("state-abc", null, "github",
                "http://localhost:8080/auth/callback", Set.of("read:user"));
        cookieService.write(response, state);
        String raw = cookieValueOf(response.getHeader("Set-Cookie"));

        String tampered = raw.substring(0, raw.length() - 3) + "AAA";

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("auth_flow", tampered));
        assertThat(cookieService.read(request)).isEmpty();
    }

    @Test
    @DisplayName("쿠키 부재·무의미 값 — empty")
    void missingOrGarbageCookieRejected() {
        assertThat(cookieService.read(new MockHttpServletRequest())).isEmpty();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("auth_flow", "no-signature-dot"));
        assertThat(cookieService.read(request)).isEmpty();
    }

    @Test
    @DisplayName("clear — Max-Age=0·같은 Path로 삭제 발행")
    void clearEmitsExpiredCookie() {
        cookieService.clear(response);
        String setCookie = response.getHeader("Set-Cookie");

        assertThat(setCookie).startsWith("auth_flow=");
        assertThat(setCookie).contains("Max-Age=0");
        assertThat(setCookie).contains("Path=/api/v1/auth");
    }

    private static String cookieValueOf(String setCookieHeader) {
        return setCookieHeader.substring("auth_flow=".length(), setCookieHeader.indexOf(';'));
    }
}
