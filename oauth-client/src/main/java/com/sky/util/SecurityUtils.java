package com.sky.util;

import cn.hutool.core.util.StrUtil;
import com.sky.constant.SecurityConstants;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @ClassName SecurityUtils
 * @Description TODO
 * @Author sky
 * @Date 2023/5/18 10:59
 * @Version 1.0
 **/
public class SecurityUtils {

    /**
     * 获取 Authentication
     *
     * @return Authentication
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static Jwt getJwt() {
        Authentication authentication = SecurityUtils.getAuthentication();
        Object principal = authentication.getPrincipal();
        if (principal instanceof Jwt) {
            return (Jwt) principal;
        }
        return null;
    }

    /**
     * 获取用户名
     *
     * @return 用户名
     */
    public static String getUserName() {
        return getAuthentication().getName();
    }

    /**
     * 获取当前用户的授权
     * @return 当前用户的授权
     */
    public static List<String> getAuthorities(){
        Jwt jwt = getJwt();
        if(jwt == null) {
            return Collections.emptyList();
        }

        return jwt.getClaimAsStringList("authorities")
                .stream()
                .map(e -> StrUtil.removePrefix(e, SecurityConstants.ROLE))
                .collect(Collectors.toList());
    }
}
