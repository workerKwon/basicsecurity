package io.security.basicsecurity.config;

import io.security.basicsecurity.config.handler.AccessDeniedExceptionHandler;
import io.security.basicsecurity.config.handler.AuthenticationExceptionHandler;
import io.security.basicsecurity.config.handler.FailureHandler;
import io.security.basicsecurity.config.handler.SuccessHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@Order(1) // 이걸 0으로 바꾸고 /secondConfig로 접근하면 이 클래스의 필터가 먼저 동작하고, 이 필터는 모든 경로에 대해 인증이 필요하기 때문에 로그인 페이지로 이동된다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final SuccessHandler successHandler;
    private final FailureHandler failureHandler;
    private final AuthenticationExceptionHandler authenticationExceptionHandler;
    private final AccessDeniedExceptionHandler accessFailureHandler;

    public SecurityConfig(UserDetailsService userDetailsService, SuccessHandler successHandler, FailureHandler failureHandler, AuthenticationExceptionHandler authenticationExceptionHandler, AccessDeniedExceptionHandler accessFailureHandler) {
        this.userDetailsService = userDetailsService;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.authenticationExceptionHandler = authenticationExceptionHandler;
        this.accessFailureHandler = accessFailureHandler;
    }

    /**
     * 계정 관리자 빌더를 통해 계정을 생성할 수 있다.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin()
//                .loginPage("/loginPage") // 로그인하는 페이지 url 경로 (인증 없이도 접근이 가능하도록 해줘야함)
//                .defaultSuccessUrl("/") // 로그인 성공하면 가지는 url 경로
                .failureUrl("/login") // 로그인 실패하면 가지는 url 경로
                .usernameParameter("userId") // 로그인 id key
                .passwordParameter("passwd") // 로그인 password key
                .loginProcessingUrl("/login_proc") // form action url
                .successHandler(successHandler)
                .failureHandler(failureHandler)
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
                .deleteCookies("remember-me");

        http
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);

        http
                .sessionManagement() // 동시세션 제어 관리
                .maximumSessions(1) // 최대 동시 세션 수
                .maxSessionsPreventsLogin(true) // true : 동시 세션 차단 전략(로그인을 실패하게 하는 전략, false : 기존 로그인 되어있는 계정을 로그아웃 시키는 전략
                .and()
                .sessionFixation().changeSessionId(); // 세션 고정 보호. changeSessionId가 기본값이라서 안해줘도 된다.

        http
                .exceptionHandling()
//                .authenticationEntryPoint(authenticationExceptionHandler) // 인증 실패 에러 처리 핸들러
                .accessDeniedHandler(accessFailureHandler); // 인가 실패 에러 처리 핸들러
    }
}
