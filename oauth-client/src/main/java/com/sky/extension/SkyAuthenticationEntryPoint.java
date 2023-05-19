package com.sky.extension;

import com.sky.util.HttpEndpointUtils;
import lombok.SneakyThrows;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName SkyAuthenticationEntryPoint
 * @Description TODO
 * @Author sky
 * @Date 2023/5/18 10:48
 * @Version 1.0
 **/
public class SkyAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    @SneakyThrows
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
        ServletServerHttpResponse servletServerHttpResponse = new ServletServerHttpResponse(response);
        Map<String, Object> error = new HashMap<>();
        if(authException instanceof InvalidBearerTokenException){
            servletServerHttpResponse.setStatusCode(HttpStatus.FAILED_DEPENDENCY);
            error.put("code", 403);
            error.put("msg", "INVALID_GRANT");
//            error = ResponseData.error(ResponseStatusEnum.INVALID_GRANT, authException.getMessage());
        }else{
            error.put("code", 403);
            error.put("msg", "UNAUTHORIZED");
            servletServerHttpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
//            error = ResponseData.error(ResponseStatusEnum.UNAUTHORIZED, authException.getMessage());
        }

        HttpEndpointUtils.writeWithMessageConverters(error, servletServerHttpResponse);
    }
}
