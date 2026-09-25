package net.java21.crowfoot.auth.blacklist;

import lombok.extern.slf4j.Slf4j;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Redis 블랙리스트 — SET key value EX seconds·MGET 1회 (02-auth/requirements.md Section 1.4.7).
 * Redis 접근 불가 시 SERVICE_UNAVAILABLE로 정규화해 올린다(fail-closed — introspection이 503으로 막힌다).
 * 원인 스택은 로그로 남기고, resultMessage는 번들 키(로케일 해석)로 내보낸다.
 */
@Slf4j
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
            log.error("블랙리스트 등록 실패(jti={})", jti, e);
            throw BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE, "detail.blacklist.register");
        }
    }

    @Override
    public void registerSession(String sid, Duration ttl) {
        try {
            redisTemplate.opsForValue().set("bl:sid:" + sid, "REVOKED", ttl);
        } catch (RuntimeException e) {
            log.error("블랙리스트 등록 실패(sid={})", sid, e);
            throw BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE, "detail.blacklist.register");
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
            log.error("블랙리스트 조회 실패(jti={}, sid={})", jti, sid, e);
            throw BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE, "detail.blacklist.lookup");
        }
    }
}
