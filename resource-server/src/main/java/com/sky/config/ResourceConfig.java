package com.sky.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @ClassName ResourceConfig
 * @Description TODO
 * @Author sky
 * @Date 2023/5/17 13:43
 * @Version 1.0
 **/
@Configuration
public class ResourceConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        return security
                .authorizeRequests(
                        request -> request
                                .mvcMatchers("/test").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2ResourceServer().jwt()
                .and()
                .and()
                .build();
    }
}
