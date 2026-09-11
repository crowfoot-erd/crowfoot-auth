package net.java21.crowfoot.auth.blacklist;

import net.java21.crowfoot.auth.testsupport.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryBlacklistStoreTest {

    private MutableClock clock;
    private InMemoryBlacklistStore store;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        store = new InMemoryBlacklistStore(clock);
    }

    @Test
    @DisplayName("Access 토큰 등록 — jti로 차단, 만료 시각 도달 시 해제")
    void accessTokenBlockAndExpiry() {
        store.registerAccessToken("jti-1", "LOGOUT", Duration.ofMinutes(30));

        assertThat(store.findBlocked("jti-1", "sid-1").tokenBlocked()).isTrue();

        clock.advanceBy(Duration.ofMinutes(30).plusSeconds(1));
        assertThat(store.findBlocked("jti-1", "sid-1").blocked()).isFalse();
    }

    @Test
    @DisplayName("세션 등록 — sid 차단이면 같은 sid의 어떤 jti도 차단")
    void sessionBlockCoversAllTokens() {
        store.registerSession("sid-1", Duration.ofMinutes(60));

        BlacklistStore.BlockResult result = store.findBlocked("any-jti", "sid-1");

        assertThat(result.sessionBlocked()).isTrue();
        assertThat(result.blocked()).isTrue();
    }

    @Test
    @DisplayName("미등록 — 차단 아님")
    void notRegisteredIsNotBlocked() {
        assertThat(store.findBlocked("jti-x", "sid-x").blocked()).isFalse();
    }
}
