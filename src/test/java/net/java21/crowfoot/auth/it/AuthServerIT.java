package net.java21.crowfoot.auth.it;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 인증 서버 전체 라이프사이클(AuthServerIT) — 시작→교환→introspect→재발급(ROTATED)→재사용 감지(409)→
 * 로그아웃→introspect(REVOKED). core 내부 API와 GitHub 토큰·UserInfo를 MockWebServerDispatcher로 대체하고,
 * 블랙리스트는 test 프로필 memory 스토어로 구동한다(RANDOM_PORT + TestRestTemplate).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
// Boot 4 — TestRestTemplate는 자동구성이 아니라 명시 활성화(spring-boot-resttestclient)
@AutoConfigureTestRestTemplate
@ActiveProfiles("test")
class AuthServerIT {

    private static final MockWebServer mockWebServer = new MockWebServer();
    private static final AtomicInteger rotateCalls = new AtomicInteger();

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeEach
    void disableRedirects() {
        // 기본 팩토리는 302를 자동 추적해 github.com까지 가버린다 — 시작 API는 Location만 검증
        restTemplate.getRestTemplate().setRequestFactory(new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()));
    }

    // 컨텍스트 로드(@DynamicPropertySource 평가)보다 서버가 먼저 떠 있어야 한다 → static 초기화
    static {
        mockWebServer.setDispatcher(new CoreAndGithubDispatcher());
        try {
            mockWebServer.start();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("MockWebServer 기동 실패", e);
        }
    }

    @AfterAll
    static void stopMocks() throws Exception {
        mockWebServer.shutdown();
    }

    // DynamicPropertyRegistry 파라미터 방식 — Framework 7.0.8 기준 유일하게 지원되는 형태.
    // (DynamicPropertyRegistrar는 람다 등록 콜백용 별도 인터페이스 — @DynamicPropertySource에는 쓸 수 없다)
    @DynamicPropertySource
    static void mockProperties(DynamicPropertyRegistry registry) {
        String base = mockWebServer.url("/").toString();
        registry.add("spring.cloud.discovery.client.simple.instances.crowfoot-core-api[0].uri", () -> base);
        registry.add("spring.security.oauth2.client.provider.github.token-uri", () -> base + "github-token");
        registry.add("spring.security.oauth2.client.provider.github.user-info-uri", () -> base + "github-user");
    }

    @Test
    @DisplayName("전체 라이프사이클 — 시작 302→교환 200(쿠키)→active→재발급 ROTATED→재사용 409→로그아웃→REVOKED")
    void fullLoginLifecycle() {
        // 1. 로그인 시작 — 302 + auth_flow 쿠키, Location에서 state 회수
        ResponseEntity<Void> start = restTemplate.exchange("/auth/oauth2/github", HttpMethod.GET,
                new HttpEntity<>(startHeaders()), Void.class);
        assertThat(start.getStatusCode().value()).isEqualTo(302);
        String location = start.getHeaders().getFirst("Location");
        String state = queryParam(location, "state");
        String authFlow = cookieValue(start, "auth_flow");
        assertThat(state).isNotBlank();
        assertThat(authFlow).isNotBlank();
        assertThat(location).contains("redirect_uri=http://localhost:8080/auth/callback");

        // 2. 교환 — 200 accessToken + crowfoot_refresh 쿠키 발행·auth_flow 삭제
        HttpHeaders exchangeHeaders = new HttpHeaders();
        exchangeHeaders.setContentType(MediaType.APPLICATION_JSON);
        exchangeHeaders.add(HttpHeaders.COOKIE, "auth_flow=" + authFlow);
        ResponseEntity<String> exchange = restTemplate.exchange("/auth/oauth2/github/token", HttpMethod.POST,
                new HttpEntity<>("{\"code\":\"gh-code\",\"state\":\"" + state + "\"}", exchangeHeaders), String.class);
        assertThat(exchange.getStatusCode().value()).isEqualTo(200);
        String accessToken = JSON.readValue(exchange.getBody(), Map.class)
                .get("response") instanceof Map resp ? ((String) resp.get("accessToken")) : null;
        assertThat(accessToken).isNotBlank();
        String refreshCookie = cookieValue(exchange, "crowfoot_refresh");
        assertThat(refreshCookie).isNotBlank();
        assertThat(exchange.getHeaders().get(HttpHeaders.SET_COOKIE).toString()).contains("auth_flow=;");

        // 3. introspect — active·sub=42(gateway가 소비하는 형상)
        ResponseEntity<String> introspect = introspect(accessToken);
        assertThat(introspect.getStatusCode().value()).isEqualTo(200);
        assertThat(introspect.getBody()).contains("\"active\":true").contains("\"sub\":\"42\"");

        // 4. 재발급(ROTATED) — 신규 Access·Refresh 쿠키
        HttpHeaders refreshHeaders = new HttpHeaders();
        refreshHeaders.add(HttpHeaders.COOKIE, "crowfoot_refresh=" + refreshCookie);
        ResponseEntity<String> refresh = restTemplate.exchange("/auth/refresh-token", HttpMethod.POST,
                new HttpEntity<>(refreshHeaders), String.class);
        assertThat(refresh.getStatusCode().value()).isEqualTo(200);
        assertThat(refresh.getBody()).contains("accessToken");
        String rotatedRefreshCookie = cookieValue(refresh, "crowfoot_refresh");
        assertThat(rotatedRefreshCookie).isNotBlank().isNotEqualTo(refreshCookie);

        // 5. 이전 Refresh 재사용 — core 409(AUTH_SESSION_REVOKED) → 401 AUTH_SESSION_REVOKED
        HttpHeaders reuseHeaders = new HttpHeaders();
        reuseHeaders.add(HttpHeaders.COOKIE, "crowfoot_refresh=" + refreshCookie);
        ResponseEntity<String> reuse = restTemplate.exchange("/auth/refresh-token", HttpMethod.POST,
                new HttpEntity<>(reuseHeaders), String.class);
        assertThat(reuse.getStatusCode().value()).isEqualTo(401);
        assertThat(reuse.getBody()).contains("AUTH_SESSION_REVOKED");

        // 6. 로그아웃 — 200 header-only(멱등), Bearer Access는 블랙리스트行
        HttpHeaders logoutHeaders = new HttpHeaders();
        logoutHeaders.add(HttpHeaders.COOKIE, "crowfoot_refresh=" + rotatedRefreshCookie);
        logoutHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        ResponseEntity<String> logout = restTemplate.exchange("/auth/logout", HttpMethod.POST,
                new HttpEntity<>(logoutHeaders), String.class);
        assertThat(logout.getStatusCode().value()).isEqualTo(200);
        assertThat(logout.getBody()).contains("\"isSuccessful\":true").doesNotContain("accessToken");

        // 7. introspect — 로그아웃한 Access는 active=false·REVOKED
        ResponseEntity<String> revoked = introspect(accessToken);
        assertThat(revoked.getBody()).contains("\"active\":false").contains("\"inactiveReason\":\"REVOKED\"");
    }

    private HttpHeaders startHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Forwarded-For", "203.0.113.7, 10.0.0.1");
        return headers;
    }

    private ResponseEntity<String> introspect(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return restTemplate.exchange("/internal/auth/introspect", HttpMethod.POST,
                new HttpEntity<>("token=" + token, headers), String.class);
    }

    private static String queryParam(String url, String key) {
        String query = url.substring(url.indexOf('?') + 1);
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(key)) {
                return kv[1];
            }
        }
        return null;
    }

    private static String cookieValue(ResponseEntity<?> response, String name) {
        List<String> setCookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        if (setCookies == null) {
            return null;
        }
        for (String setCookie : setCookies) {
            if (setCookie.startsWith(name + "=")) {
                int end = setCookie.indexOf(';');
                return end < 0 ? setCookie.substring(name.length() + 1)
                        : setCookie.substring(name.length() + 1, end);
            }
        }
        return null;
    }

    /** core 내부 API(공통 포맷 래핑)·GitHub 토큰/UserInfo 응답 — rotate는 2회차부터 재사용 감지(409) */
    private static class CoreAndGithubDispatcher extends Dispatcher {

        @Override
        public MockResponse dispatch(RecordedRequest request) {
            String path = request.getPath();
            if (path == null) {
                return notFound();
            }
            if (path.startsWith("/github-token")) {
                return json(200, "{\"access_token\":\"gh-access-token\",\"token_type\":\"bearer\","
                        + "\"expires_in\":28800,\"scope\":\"read:user\"}");
            }
            if (path.startsWith("/github-user")) {
                return json(200, "{\"id\":12345,\"login\":\"octocat\",\"name\":\"Octo Cat\"}");
            }
            if (path.startsWith("/internal/core/providers")) {
                return json(200, "{\"header\":{\"isSuccessful\":true,\"resultCode\":\"SUCCESS\",\"resultMessage\":\"SUCCESS\"},"
                        + "\"responses\":[{\"code\":\"github\",\"displayName\":\"GitHub\"}],\"totalCount\":1}");
            }
            if (path.startsWith("/internal/core/users:get-or-create")) {
                return json(200, "{\"header\":{\"isSuccessful\":true,\"resultCode\":\"SUCCESS\",\"resultMessage\":\"SUCCESS\"},"
                        + "\"response\":{\"userId\":\"42\",\"created\":true,\"admin\":false}}");
            }
            if (path.startsWith("/internal/core/refresh-tokens:rotate")) {
                if (rotateCalls.incrementAndGet() == 1) {
                    return json(200, "{\"header\":{\"isSuccessful\":true,\"resultCode\":\"SUCCESS\",\"resultMessage\":\"SUCCESS\"},"
                            + "\"response\":{\"verdict\":\"ROTATED\",\"latestJti\":null}}");
                }
                return json(409, "{\"header\":{\"isSuccessful\":false,\"resultCode\":\"AUTH_SESSION_REVOKED\",\"resultMessage\":\"재사용 감지\"}}");
            }
            if (path.equals("/internal/core/refresh-tokens") || path.startsWith("/internal/core/audit-logs")) {
                return json(201, "{\"header\":{\"isSuccessful\":true,\"resultCode\":\"SUCCESS\",\"resultMessage\":\"SUCCESS\"}}");
            }
            if (path.startsWith("/internal/core/refresh-tokens/")) {
                return new MockResponse().setResponseCode(204);
            }
            return notFound();
        }

        private MockResponse json(int status, String body) {
            return new MockResponse().setResponseCode(status)
                    .setHeader("Content-Type", "application/json")
                    .setBody(body);
        }

        private MockResponse notFound() {
            return json(404, "{\"header\":{\"isSuccessful\":false,\"resultCode\":\"RESOURCE_NOT_FOUND\",\"resultMessage\":\"없음\"}}");
        }
    }
}
