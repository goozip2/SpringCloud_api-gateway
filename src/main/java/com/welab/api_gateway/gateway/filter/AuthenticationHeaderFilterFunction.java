package com.welab.api_gateway.gateway.filter;

import com.welab.api_gateway.common.util.HttpUtils;
import com.welab.api_gateway.security.jwt.authentication.UserPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;

import java.util.function.Function;

// 현재 로그인된 사용자의 인증 정보를 HTTP 요청 헤더에 추가
class AuthenticationHeaderFilterFunction {
    public static Function<ServerRequest, ServerRequest> addHeader() {
        return request -> {
            ServerRequest.Builder requestBuilder = ServerRequest.from(request);
            // 현재 요청의 Security Context에서 인증된 사용자의 정보 가져오기
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            // instanceof: 객체가 특정 클래스나 인터페이스의 인스턴스인지 확인
            // principal이 UserPrincipal 타입인 경우에만 내부 로직 실행
            if (principal instanceof UserPrincipal userPrincipal) {
                // downstream 마이크로서비스에서 받아 사용자 식별에 활용
                requestBuilder.header("X-Auth-UserId", userPrincipal.getUserId());
                // 필요시 권한 정보 입력
                // requestBuilder.header("X-Auth-Authorities", ...);
            }
            // String remoteAddr = HttpUtils.getRemoteAddr(requestBuildert.servletRequest());
            // 클라이언트의 IP를 동적으로 받아옴
            String remoteAddr = HttpUtils.getRemoteAddr(request.servletRequest());
            requestBuilder.header("X-Client-Address", remoteAddr);
            // 실제로는 User-Agent 파싱 등을 통해 자동 판별
            String device = "WEB";
            requestBuilder.header("X-Client-Device", device);
            return requestBuilder.build();
        };
    }
}
