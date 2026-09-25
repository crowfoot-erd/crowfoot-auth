package net.java21.crowfoot.auth.common.web;

import net.java21.crowfoot.auth.common.ErrorResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.common.i18n.ServerMessages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * resultMessage 로케일 해석 (api-design.md §5.7 — core 미러) — 번들 주입 상태에서
 * BusinessException 우선순위(번들 키 → 생성자 리터럴 → error.{code} → 기본 문구)를 검증한다.
 */
class ResultMessageLocaleTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @BeforeEach
    void setUp() {
        ServerMessages.init(messageSource());
    }

    @AfterEach
    void tearDown() {
        ServerMessages.init(null);
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    @DisplayName("번들 키(BusinessException.of)는 요청 로케일 문구로 해석된다 — args {0} 치환 포함")
    void resolvesKeyPerLocale() {
        LocaleContextHolder.setLocale(Locale.JAPANESE);
        assertThat(resultMessage(BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE,
                "detail.refresh.unknown-verdict", "WEIRD")))
                .isEqualTo("不明な rotation verdict です: WEIRD");

        LocaleContextHolder.setLocale(Locale.SIMPLIFIED_CHINESE);
        assertThat(resultMessage(BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE,
                "detail.core.unavailable")))
                .isEqualTo("与 core 服务通信失败");

        LocaleContextHolder.setLocale(Locale.KOREAN);
        assertThat(resultMessage(BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE,
                "detail.blacklist.lookup")))
                .isEqualTo("블랙리스트 조회 실패");

        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertThat(resultMessage(BusinessException.of(ErrorCode.SERVICE_UNAVAILABLE,
                "detail.blacklist.register")))
                .isEqualTo("Failed to register the blacklist entry");
    }

    @Test
    @DisplayName("ErrorCode만 던지면 error.{code} 번들 문구로 해석된다")
    void resolvesErrorCodeKey() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertThat(resultMessage(new BusinessException(ErrorCode.AUTH_TOKEN_INVALID)))
                .isEqualTo("The token is not valid");

        LocaleContextHolder.setLocale(Locale.JAPANESE);
        assertThat(resultMessage(new BusinessException(ErrorCode.USER_WITHDRAWN)))
                .isEqualTo("退会したアカウントです");
    }

    @Test
    @DisplayName("생성자 리터럴 문구는 번들 error.*보다 우선한다 — 미전환 도메인 문구 호환")
    void customLiteralWinsOverBundle() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertThat(resultMessage(new BusinessException(ErrorCode.AUTH_TOKEN_INVALID, "재사용 감지")))
                .isEqualTo("재사용 감지");
    }

    @Test
    @DisplayName("로케일 컨텍스트가 없으면 기본(ko) 번들로 해석된다")
    void defaultsToKoreanWithoutLocaleContext() {
        LocaleContextHolder.resetLocaleContext();
        assertThat(resultMessage(new BusinessException(ErrorCode.AUTH_TOKEN_EXPIRED)))
                .isEqualTo("토큰이 만료되었습니다");
    }

    @Test
    @DisplayName("미등록 키는 error.{code} 번들 문구(로케일)로 폴백한다")
    void unknownKeyFallsBackToErrorCodeBundle() {
        LocaleContextHolder.setLocale(Locale.JAPANESE);
        assertThat(resultMessage(BusinessException.of(ErrorCode.AUTH_STATE_INVALID, "detail.no-such-key")))
                .isEqualTo("ログインリクエスト情報が無効です");
    }

    private String resultMessage(BusinessException ex) {
        ErrorResponse response = handler.handleBusiness(ex).getBody();
        return response.header().resultMessage();
    }

    /** 운영과 동일 구성 — spring.messages.basename 두 벌, 시스템 로케일 폴백 없음 */
    private static MessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasenames("i18n/messages", "i18n/validation/ValidationMessages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
