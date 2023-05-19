package com.sky.handler;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.StrUtil;
import com.sky.constant.SecurityConstants;
import com.sky.util.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.PatternMatchUtils;
import org.springframework.util.StringUtils;

import java.util.Collection;

/**
 * @ClassName PermissionHandler
 * @Description TODO
 * @Author sky
 * @Date 2023/5/18 10:56
 * @Version 1.0
 **/
public class PermissionHandler {

    public boolean hasPermission(String... permissions) {
        if (ArrayUtil.isEmpty(permissions)) {
            return false;
        }
        Authentication authentication = SecurityUtils.getAuthentication();
        if (authentication == null) {
            return false;
        }
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .map(e -> StrUtil.removePrefix(e, SecurityConstants.ROLE))
                .filter(StringUtils::hasText)
                .anyMatch(e -> PatternMatchUtils.simpleMatch(permissions, e));
    }
}
