package net.java21.crowfoot.auth.blacklist;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 메모리 블랙리스트 — 테스트·local(방화벽으로 Redis 불가 기간) 우회 구현.
 * 값은 사유·만료 시각을 담은 엔트리로 저장하고 조회 시 만료 항목은 제거된 것으로 본다.
 */
public class InMemoryBlacklistStore implements BlacklistStore {

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryBlacklistStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void registerAccessToken(String jti, String reason, Duration ttl) {
        entries.put("bl:at:" + jti, new Entry(reason, clock.instant().plus(ttl)));
    }

    @Override
    public void registerSession(String sid, Duration ttl) {
        entries.put("bl:sid:" + sid, new Entry("REVOKED", clock.instant().plus(ttl)));
    }

    @Override
    public BlockResult findBlocked(String jti, String sid) {
        Instant now = clock.instant();
        boolean tokenBlocked = blocked("bl:at:" + jti, now);
        boolean sessionBlocked = blocked("bl:sid:" + sid, now);
        return new BlockResult(tokenBlocked, sessionBlocked);
    }

    private boolean blocked(String key, Instant now) {
        Entry entry = entries.get(key);
        if (entry == null) {
            return false;
        }
        if (!now.isBefore(entry.expiresAt())) {
            entries.remove(key);
            return false;
        }
        return true;
    }

    private record Entry(String reason, Instant expiresAt) {
    }
}
