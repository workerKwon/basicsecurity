package io.security.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@Order(0) // 더 구체적인 경로에 대한 설정을 앞에 둬야 한다.
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/secondConfig/**")
                .authorizeRequests()
                .anyRequest().permitAll() // 인증 없이도 secondConfig 하위의 모든 경로에 접근 가능하다.
                .and()
                .httpBasic();
    }
}
