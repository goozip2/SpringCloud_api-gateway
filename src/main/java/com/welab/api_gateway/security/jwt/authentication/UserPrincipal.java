package com.welab.api_gateway.security.jwt.authentication;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.security.Principal;
import java.util.Objects;

@Getter
@RequiredArgsConstructor
// Spring Security 측에서 관리하는 변조되지 않는 유저 정보 (안전)
public class UserPrincipal implements Principal {
    private final String userId;

    public boolean hasName() {
        return userId != null;
    }

    // 필수 항목 존재 여부 판단
    public boolean hasMandatory() {
        return userId != null;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public String getName() {
        return userId;
    }

    @Override
    public boolean equals(Object another) {
        if (this == another) return true;
        if (another == null) return false;
        if (!getClass().isAssignableFrom(another.getClass())) return false;
        UserPrincipal principal = (UserPrincipal) another;
        if (!Objects.equals(userId, principal.userId)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = userId != null ? userId.hashCode() : 0;
        return result;
    }
}
