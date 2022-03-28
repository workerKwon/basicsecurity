package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
//                .loginPage("/loginPage") // 로그인하는 페이지 url 경로 (인증 없이도 접근이 가능하도록 해줘야함)
                .defaultSuccessUrl("/") // 로그인 성공하면 가지는 url 경로
                .failureUrl("/login") // 로그인 실패하면 가지는 url 경로
                .usernameParameter("userId") // 로그인 id key
                .passwordParameter("passwd") // 로그인 password key
                .loginProcessingUrl("/login_proc") // form action url
                .successHandler(new AuthenticationSuccessHandler() { // 익명 클래스 객체를 사용해서 handler 세팅
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName());
                        response.sendRedirect("/"); // 성공하면 root로 이동하도록 핸들러를 작성. defaultSuccessUrl 해놓은 설정과 중복되는 설정.
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception = " + exception.getMessage());
                        response.sendRedirect("/login"); // 실패하면 /login 으로 이동하도록 실패 핸들러 작성. failureUrl 로 해놓은 설정과 중복되는 설정
                    }
                })
                .permitAll();
    }
}
