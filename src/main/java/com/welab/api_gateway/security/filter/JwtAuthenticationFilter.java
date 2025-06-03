package com.welab.api_gateway.security.filter;

import com.welab.api_gateway.security.jwt.JwtTokenValidator;
import com.welab.api_gateway.security.jwt.authentication.JwtAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // getToken: Request Header에서 Token 정보 가져옴
        String jwtToken = jwtTokenValidator.getToken(request);
        if (jwtToken != null) {
            // Token이 존재한다면,
            // Token 검증 (정보 존재 여부, 만료 여부, access Token 여부)
            // 유효할 경우 SecurityContextHolder에 사용자 정보 저장
            JwtAuthentication authentication = jwtTokenValidator.validateToken(jwtToken);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
