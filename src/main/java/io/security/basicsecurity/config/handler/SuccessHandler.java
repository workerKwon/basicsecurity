package io.security.basicsecurity.config.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class SuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("authentication = " + authentication.getName());

        // 로그인 인증 실패 했을 때 사용자가 로그인해서 가려고 했던 주소를 기억하고 있는 클래스
        HttpSessionRequestCache httpSessionRequestCache = new HttpSessionRequestCache();
        SavedRequest savedRequest = httpSessionRequestCache.getRequest(request, response);
        String redirectUrl = savedRequest.getRedirectUrl(); // 저장된 리다이렉트 URL을 가져온다.

        // 성공하면 사용자가 가려고 했던 URL 주소로 이동하도록 핸들러를 작성. defaultSuccessUrl 해놓은 설정과 중복되는 설정.
        response.sendRedirect(redirectUrl);
    }
}
