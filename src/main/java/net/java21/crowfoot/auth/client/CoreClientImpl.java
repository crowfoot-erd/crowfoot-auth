package net.java21.crowfoot.auth.client;

import feign.FeignException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.java21.crowfoot.auth.client.dto.CreateAuditLogRequest;
import net.java21.crowfoot.auth.client.dto.GetOrCreateUserRequest;
import net.java21.crowfoot.auth.client.dto.GetOrCreateUserResponse;
import net.java21.crowfoot.auth.client.dto.ProviderResponse;
import net.java21.crowfoot.auth.client.dto.RegisterRefreshTokenRequest;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenRequest;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenResponse;
import net.java21.crowfoot.auth.common.ApiResponse;
import net.java21.crowfoot.auth.common.ListApiResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.List;

/**
 * core 내부 API 호출 구현 — Feign 전송({@link CoreFeignClient})의 응답 해석·에러 매핑.
 *
 * <p>에러 변환: core 404/409는 본문 resultCode를 {@link CoreCallException}으로 전파하고,
 * 그 외(5xx·타임아웃·연결 거부·본문 파식 실패)는 fail-closed로 SERVICE_UNAVAILABLE을 던진다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CoreClientImpl implements CoreClient {

    private final CoreFeignClient coreFeignClient;
    private final ObjectMapper objectMapper;

    @Override
    public GetOrCreateUserResponse getOrCreateUser(String provider, String providerUserId, String username, String email, String name) {
        try {
            return requireSuccess(coreFeignClient.getOrCreate(
                    new GetOrCreateUserRequest(provider, providerUserId, username, email, name))).response();
        } catch (FeignException e) {
            throw translate(e);
        }
    }

    @Override
    public void registerRefreshToken(long userId, String jti, String sid, Instant expiresAt, String ip, String userAgent) {
        try {
            coreFeignClient.registerRefreshToken(new RegisterRefreshTokenRequest(
                    Long.toString(userId), jti, sid, expiresAt, ip, userAgent));
        } catch (FeignException e) {
            throw translate(e);
        }
    }

    @Override
    public RotateRefreshTokenResponse rotateRefreshToken(long userId, String currentJti, String newJti, Instant newExpiresAt) {
        try {
            return requireSuccess(coreFeignClient.rotate(new RotateRefreshTokenRequest(
                    Long.toString(userId), currentJti, newJti, newExpiresAt))).response();
        } catch (FeignException e) {
            throw translate(e);
        }
    }

    @Override
    public void revokeRefreshToken(String jti) {
        try {
            coreFeignClient.revokeRefreshToken(jti);
        } catch (FeignException e) {
            throw translate(e);
        }
    }

    @Override
    public void revokeSession(String sid) {
        try {
            coreFeignClient.revokeSession(sid);
        } catch (FeignException e) {
            throw translate(e);
        }
    }

    @Override
    public void recordAuditLog(long actorId, String action, String detail) {
        try {
            coreFeignClient.recordAudit(new CreateAuditLogRequest(Long.toString(actorId), action, detail));
        } catch (Exception e) {
            // best-effort — 감사 기록 실패가 본류(로그인·재발급·로그아웃)를 실패시키지 않는다
            log.warn("감사 기록 실패(action={}, actorId={}) — best-effort 무시", action, actorId, e);
        }
    }

    @Override
    public List<ProviderResponse> activeProviders() {
        try {
            ListApiResponse<ProviderResponse> body = coreFeignClient.providers();
            if (body == null || !body.header().isSuccessful()) {
                throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE);
            }
            return body.responses();
        } catch (FeignException e) {
            throw translate(e);
        }
    }

    /** 2xx인데 header가 실패를 담은 경우(계약 밖) — resultCode를 그대로 전파한다 */
    private <T> ApiResponse<T> requireSuccess(ApiResponse<T> body) {
        if (body == null || body.header() == null || !body.header().isSuccessful()) {
            throw new CoreCallException(
                    body != null && body.header() != null ? body.header().resultCode() : "UNKNOWN",
                    "core 응답 header가 실패를 담고 있다");
        }
        return body;
    }

    /** core 404/409는 도메인 결과 resultCode 전파, 그 외·파싱 실패는 fail-closed 503 */
    private RuntimeException translate(FeignException e) {
        int status = e.status();
        if (status == 404 || status == 409) {
            String resultCode = readResultCode(e);
            if (resultCode != null) {
                return new CoreCallException(resultCode, "core 도메인 결과: " + resultCode);
            }
        }
        log.warn("core 호출 실패(status={}) — SERVICE_UNAVAILABLE으로 변환", status, e);
        return new BusinessException(ErrorCode.SERVICE_UNAVAILABLE);
    }

    private String readResultCode(FeignException e) {
        try {
            JsonNode root = objectMapper.readTree(e.contentUTF8());
            JsonNode code = root.path("header").path("resultCode");
            return code.isMissingNode() ? null : code.asString();
        } catch (Exception parseEx) {
            return null;
        }
    }
}
