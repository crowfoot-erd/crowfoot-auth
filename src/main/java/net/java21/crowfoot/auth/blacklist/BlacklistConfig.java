package net.java21.crowfoot.auth.blacklist;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Clock;

/**
 * 블랙리스트 저장소 선택 — crowfoot.auth.blacklist.store 프로퍼티(redis | memory).
 * local은 방화벽으로 Redis가 막혀 있는 기간 memory로 우회한다.
 */
@Configuration
public class BlacklistConfig {

    @Bean
    @ConditionalOnProperty(name = "crowfoot.auth.blacklist.store", havingValue = "redis")
    public BlacklistStore redisBlacklistStore(StringRedisTemplate stringRedisTemplate) {
        return new RedisBlacklistStore(stringRedisTemplate);
    }

    @Bean
    @ConditionalOnProperty(name = "crowfoot.auth.blacklist.store", havingValue = "memory")
    public BlacklistStore inMemoryBlacklistStore(Clock clock) {
        return new InMemoryBlacklistStore(clock);
    }
}
