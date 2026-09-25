package net.java21.crowfoot.auth.common.i18n;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.MessageSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.MessageSource;
import org.springframework.context.support.DelegatingMessageSource;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 운영 구성 재현 — spring.messages 프로퍼티로 만들어지는 MessageSource 빈이
 * error 계열 키를 로케일로 실제로 해석하는지 검증한다(core 미러 — 런타임 회귀 방어).
 * 중립 번들(i18n/messages.properties)이 없으면 Boot 자동구성이 스킵돼
 * DelegatingMessageSource로 떨어지는 v1.16 배포 결함을 잡는 파수꾼.
 */
class MessageSourceBootWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MessageSourceAutoConfiguration.class))
            .withPropertyValues(
                    "spring.messages.basename=i18n/messages,i18n/validation/ValidationMessages",
                    "spring.messages.encoding=UTF-8",
                    "spring.messages.fallback-to-system-locale=false");

    @Test
    @DisplayName("Boot 자동구성 MessageSource가 application.yml과 동일 프로퍼티에서 error.* 키를 로케일 해석한다")
    void bootMessageSourceResolvesErrorKeys() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(MessageSource.class);
            MessageSource source = context.getBean(MessageSource.class);
            assertThat(source).isNotInstanceOf(DelegatingMessageSource.class);
            assertThat(source.getMessage("error.auth_token_invalid", null, null, Locale.JAPANESE))
                    .isEqualTo("トークンが無効です");
            assertThat(source.getMessage("error.auth_token_invalid", null, null, Locale.ENGLISH))
                    .isEqualTo("The token is not valid");
        });
    }
}
