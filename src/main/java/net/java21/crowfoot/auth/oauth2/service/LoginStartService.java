package net.java21.crowfoot.auth.oauth2.service;

import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.ProviderResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.oauth2.AuthFlowCookieService;
import net.java21.crowfoot.auth.oauth2.AuthFlowState;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * 로그인 시작 (02-auth/api.md Section 3.1) — 활성 제공자 검증 → auth_flow 쿠키 발행 → authorize URL 302.
 * oauth2Login() 필터체인은 쓰지 않는다(콜백이 프론트로 가 서버에 도착하지 않음) —
 * 시작·교환은 자체 서비스가, 제공자 통신 도구는 Spring Security OAuth2 Client 구성요소를 재사용한다.
 */
@Service
public class LoginStartService {

    private final CoreClient coreClient;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final AuthFlowCookieService authFlowCookieService;

    public LoginStartService(CoreClient coreClient,
                             ClientRegistrationRepository clientRegistrationRepository,
                             AuthFlowCookieService authFlowCookieService) {
        this.coreClient = coreClient;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authFlowCookieService = authFlowCookieService;
    }

    /** @return 제공자 authorize 엔드포인트 URL — 컨트롤러가 302 Location으로 쓴다 */
    public String start(String provider, HttpServletResponse response) {
        // 활성 검증 — core 장애 시 CoreClient가 SERVICE_UNAVAILABLE을 던진다(fail-closed)
        List<ProviderResponse> providers = coreClient.activeProviders();
        if (providers.stream().noneMatch(p -> provider.equals(p.code()))) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND);
        }
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(provider);
        if (registration == null) {
            // core에는 활성이어도 yml 등록이 없으면 시작할 수 없다 — 설정 누락
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND);
        }

        String state = UUID.randomUUID().toString();
        // GitHub OAuth App은 PKCE 미지원 — codeVerifier는 null. Google 추가 시 난수 생성해 싣는다.
        AuthFlowState flowState = new AuthFlowState(state, null, provider,
                registration.getRedirectUri(), registration.getScopes());
        authFlowCookieService.write(response, flowState);
        return flowState.toAuthorizationRequest(registration).getAuthorizationRequestUri();
    }
}
