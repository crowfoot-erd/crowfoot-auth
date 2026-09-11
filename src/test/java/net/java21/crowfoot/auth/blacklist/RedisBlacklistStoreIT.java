package net.java21.crowfoot.auth.blacklist;

import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import redis.embedded.RedisServer;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * embedded Redis(codemonstur — 네이티브 바이너리, Docker 불필요)로 RedisBlacklistStore의
 * 실제 프로토콜 동작(SET EX·MGET·TTL)을 검증한다. 장애 전파는 마지막에 서버를 내려 확인.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RedisBlacklistStoreIT {

    private static final int PORT = 6390;

    private static RedisServer redisServer;
    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redisTemplate;

    private final RedisBlacklistStore store = new RedisBlacklistStore(redisTemplate);

    @BeforeAll
    static void startRedis() throws Exception {
        redisServer = new RedisServer(PORT);
        redisServer.start();
        // commandTimeout 500ms — 장애 테스트(서버 down)에서 빠르게 실패한다
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofMillis(500))
                .build();
        connectionFactory = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration("127.0.0.1", PORT), clientConfig);
        connectionFactory.afterPropertiesSet();
        redisTemplate = new StringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void stopRedis() throws Exception {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
        if (redisServer != null) {
            redisServer.stop();
        }
    }

    @Test
    @Order(1)
    @DisplayName("Access 토큰 등록(SET EX) — jti로 차단되고 TTL 지나면 해제된다")
    void registerAccessTokenWithExpiry() throws InterruptedException {
        store.registerAccessToken("jti-it-1", "LOGOUT", Duration.ofSeconds(1));

        assertThat(store.findBlocked("jti-it-1", "sid-it").tokenBlocked()).isTrue();

        Thread.sleep(1_500);
        assertThat(store.findBlocked("jti-it-1", "sid-it").blocked()).isFalse();
    }

    @Test
    @Order(2)
    @DisplayName("세션 등록 — sid 차단이 같은 sid의 어떤 jti도 막는다(MGET 1회)")
    void registerSessionBlocksAllTokensOfSession() {
        store.registerSession("sid-it-2", Duration.ofSeconds(60));

        BlacklistStore.BlockResult result = store.findBlocked("never-registered-jti", "sid-it-2");

        assertThat(result.tokenBlocked()).isFalse();
        assertThat(result.sessionBlocked()).isTrue();
        assertThat(result.blocked()).isTrue();
    }

    @Test
    @Order(3)
    @DisplayName("미등록 — 차단 아님")
    void notRegisteredIsNotBlocked() {
        assertThat(store.findBlocked("jti-none", "sid-none").blocked()).isFalse();
    }

    @Test
    @Order(99)
    @DisplayName("Redis 접근 불가 — SERVICE_UNAVAILABLE 전파(fail-closed)")
    void connectionFailurePropagatesAs503() throws Exception {
        redisServer.stop();

        assertThatThrownBy(() -> store.findBlocked("jti-x", "sid-x"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.SERVICE_UNAVAILABLE);
    }
}
