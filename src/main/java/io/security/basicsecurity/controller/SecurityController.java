package io.security.basicsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String page(HttpSession session) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext attribute =(SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = attribute.getAuthentication();
        System.out.println("session authentication == securityContext authentication : " + (authentication1 == authentication));

        return "home";
    }

    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() { return "userPage"; }

    @GetMapping("/admin/pay")
    public String adminPay() { return "adminPay"; }

    @GetMapping("/admin/**")
    public String admin() { return "admin"; }

    @GetMapping("/denied")
    public String denied() {return "denied";}

//    @GetMapping("/login")
//    public String login() {return "login";}
}
