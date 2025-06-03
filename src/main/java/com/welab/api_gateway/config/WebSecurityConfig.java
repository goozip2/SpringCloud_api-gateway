package com.welab.api_gateway.config;


import com.welab.api_gateway.security.filter.JwtAuthenticationFilter;
import com.welab.api_gateway.security.jwt.JwtTokenValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final JwtTokenValidator jwtTokenValidator;
    @Bean
    public SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
        http
                // CORS 설정 활성화
                .cors(httpSecurityCorsConfigurer -> {
                    httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
                })
                // CSRF 방어 기능을 비활성화
                .csrf(AbstractHttpConfigurer::disable)
                // 모든 경로(/**)에 대해 보안 설정 적용
                .securityMatcher("/**") // map current config to given resource path
                // 세션 정책을 무상태(stateless)로 설정
                .sessionManagement(sessionManagementConfigurer
                        -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 폼 로그인 기능 비활성화 (Spring Security 기본 로그인 폼 사용 X)
                .formLogin(AbstractHttpConfigurer::disable)
                // HTTP 기본 인증 비활성화 (HTTP Basic 인증 방식 사용 X)
                .httpBasic(AbstractHttpConfigurer::disable)
                // 사용자 정의 필터 등록
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtTokenValidator),
                        UsernamePasswordAuthenticationFilter.class)
                // "/api/user/v1/auth/**"로 시작하는 요청을 모두 허용 (인증 불필요)
                // 나머지 모두 인증 필요
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers("/api/user/v1/auth/**").permitAll()
                        .anyRequest().authenticated()
                );
        return http.build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // 클라이언트가 쿠키, 인증 정보(자격 증명)를 요청에 포함하는 것을 허용
        config.setAllowCredentials(true);
        // config.setAllowedOrigins(List.of("*")); (보안상 제한)
        // 모든 출처(origin)에서 오는 요청 허용
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}