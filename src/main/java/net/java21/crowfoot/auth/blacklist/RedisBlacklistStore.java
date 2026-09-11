package net.java21.crowfoot.auth.blacklist;

import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Redis 블랙리스트 — SET key value EX seconds·MGET 1회 (02-auth/requirements.md Section 1.4.7).
 * Redis 접근 불가 시 SERVICE_UNAVAILABLE로 정규화해 올린다(fail-closed — introspection이 503으로 막힌다).
 */
public class RedisBlacklistStore implements BlacklistStore {

    private final StringRedisTemplate redisTemplate;

    public RedisBlacklistStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void registerAccessToken(String jti, String reason, Duration ttl) {
        try {
            redisTemplate.opsForValue().set("bl:at:" + jti, reason, ttl);
        } catch (RuntimeException e) {
            throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE, "블랙리스트 등록 실패", e);
        }
    }

    @Override
    public void registerSession(String sid, Duration ttl) {
        try {
            redisTemplate.opsForValue().set("bl:sid:" + sid, "REVOKED", ttl);
        } catch (RuntimeException e) {
            throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE, "블랙리스트 등록 실패", e);
        }
    }

    @Override
    public BlockResult findBlocked(String jti, String sid) {
        try {
            List<String> values = redisTemplate.opsForValue()
                    .multiGet(List.of("bl:at:" + jti, "bl:sid:" + sid));
            boolean tokenBlocked = values != null && values.size() > 0 && Objects.nonNull(values.get(0));
            boolean sessionBlocked = values != null && values.size() > 1 && Objects.nonNull(values.get(1));
            return new BlockResult(tokenBlocked, sessionBlocked);
        } catch (RuntimeException e) {
            throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE, "블랙리스트 조회 실패", e);
        }
    }
}
