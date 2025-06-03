package com.welab.api_gateway.gateway.filter;

import org.springframework.cloud.gateway.server.mvc.common.Shortcut;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.web.servlet.function.HandlerFilterFunction.ofRequestProcessor;

// 정적 필터 함수 정의 (application-local.yml에 등록할 필터)
public interface GatewayFilterFunctions {
    // 필터 파라미터를 간단하게 작성할 수 있도록 도와주는 메타 애노테이션
    // application-local.yml에 메소드명으로 filter 등록
    @Shortcut
    static HandlerFilterFunction<ServerResponse, ServerResponse> addAuthenticationHeader() {
        // 등록할 필터 함수 지정
        return ofRequestProcessor(AuthenticationHeaderFilterFunction.addHeader());
    }
}
