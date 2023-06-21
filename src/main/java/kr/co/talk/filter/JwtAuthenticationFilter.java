package kr.co.talk.filter;

import kr.co.talk.logout.service.LogoutRedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import kr.co.talk.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class JwtAuthenticationFilter
        extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;
    private final LogoutRedisService logoutRedisService;
    private static final String USER_ID = "userId";
    private static final String LOGOUT_PATH = "/user/logout";

    @Autowired
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, LogoutRedisService logoutRedisService) {
        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
        this.logoutRedisService = logoutRedisService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange);
            }

            String authorizationHeader = headers.get(HttpHeaders.AUTHORIZATION).get(0);

            // 인증
            // Bearer 붙지 않았을 때
            if (!authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange);
            }

            String token = authorizationHeader.split("Bearer ")[1].trim();
            log.info("token info :: {}", token);

            // logout API에 적용된 액세스 토큰일 때
            if (logoutRedisService.isBlockedAccessToken(token)) {
                log.warn("This access token is blocked by logout API.");
                return onError(exchange);
            }

            // 토근 유효성 통과 안됐을시 예외 발생, userId 가져옴
            String subject = jwtTokenProvider.getAccessTokenSubject(token);
            log.info("subject:: {} ", subject);

            ServerHttpRequest serverHttpRequest = exchange.getRequest().mutate()
                    .header(USER_ID, subject)
                    .build();
            ServerWebExchange webExchange = exchange.mutate()
                    .request(serverHttpRequest)
                    .build();
            log.info("header USER_ID :: {}", webExchange.getRequest().getHeaders().get(USER_ID));

            // 로그아웃 API일때 redis에 액세스토큰 블랙리스트 등록
            if (request.getPath().toString().equals(LOGOUT_PATH) && request.getMethod() == HttpMethod.POST) {
                long leftExpirationMillis = jwtTokenProvider.getLeftExpirationMillis(token);
                logoutRedisService.blockAccessToken(token, leftExpirationMillis);
            }

            return chain.filter(webExchange);
        };
    }


    /**
     * 인증 실패 시, 권한 없음을 나타냄
     *
     * @param exchange
     * @param errorMsg
     * @param httpStatus
     * @return
     */
    private Mono<Void> onError(ServerWebExchange exchange) {
        log.error("권한 없음");

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);

        return response.setComplete();

    }


    static class Config {

    }
}
