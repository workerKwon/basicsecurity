package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;


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

        http
                .logout()
                .logoutUrl("/logout") // 로그아웃 요청 경로(POST)
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); // 세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me") //
                ;

        http
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService)
                .and()
                .sessionManagement() // 동시세션 제어 관리
                .maximumSessions(1) // 최대 동시 세션 수
                .maxSessionsPreventsLogin(true) // true : 동시 세션 차단 전략(로그인을 실패하게 하는 전략, false : 기존 로그인 되어있는 계정을 로그아웃 시키는 전략
                .and()
                .sessionFixation().changeSessionId() // 세션 고정 보호. changeSessionId가 기본값이라서 안해줘도 된다.
        ;
    }
}
