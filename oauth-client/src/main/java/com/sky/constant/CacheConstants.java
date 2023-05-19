package com.sky.constant;

/**
 * @ClassName CacheConstants
 * @Description TODO
 * @Author sky
 * @Date 2023/5/18 10:47
 * @Version 1.0
 **/
public interface CacheConstants {
    /**
     * 验证码前缀
     */
    String CAPTCHA_PREFIX = "captcha:";

    /**
     * 验证码有效期。单位：秒
     */
    Long CAPTCHA_TIME_OUT = 60L;

    /**
     * Token 前缀
     */
    String TOKEN = "token";

    /**
     * 菜单缓存 key
     */
    String CACHE_MENU = "cache_menu";

    /**
     * 用户缓存 key
     */
    String CACHE_USER = "cache_user";
}
