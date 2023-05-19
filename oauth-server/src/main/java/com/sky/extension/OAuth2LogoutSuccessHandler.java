package com.sky.extension;

/**
 * @ClassName OAuth2LogoutSuccessHandler
 * @Description TODO
 * @Author sky
 * @Date 2023/5/18 10:05
 * @Version 1.0
 **/
import com.sky.util.HttpEndpointUtils;
import lombok.SneakyThrows;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ZnPi
 * @date 2022-10-22
 */
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {
    private final HttpStatus httpStatusToReturn;

    public OAuth2LogoutSuccessHandler(HttpStatus httpStatusToReturn) {
        Assert.notNull(httpStatusToReturn, "The provided HttpStatus must not be null.");
        this.httpStatusToReturn = httpStatusToReturn;
    }

    public OAuth2LogoutSuccessHandler() {
        this.httpStatusToReturn = HttpStatus.OK;
    }

    @Override
    @SneakyThrows
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        response.setStatus(this.httpStatusToReturn.value());
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("code", 200);
        responseData.put("msg", "success");
        HttpEndpointUtils.writeWithMessageConverters(responseData, httpResponse);
    }
}
