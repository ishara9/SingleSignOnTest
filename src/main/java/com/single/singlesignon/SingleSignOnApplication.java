package com.single.singlesignon;

import java.util.Collections;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
@Configuration
public class SingleSignOnApplication {

  private static Logger logger = LoggerFactory.getLogger(SecurityFilterChain.class);

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    logger.info("filterChain");

    http.authorizeHttpRequests(
            (authz) ->
                authz
                    .requestMatchers("/", "/index.html", "/error", "/webjars/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .oauth2Login(
            o ->
                o.failureHandler(
                    (request, response, exception) -> {
                      request.getSession().setAttribute("error.message", exception.getMessage());
                      logger.debug(String.format("%s & %s & %s", request, response, exception));
                    }))
        .logout(
            logout -> {
              logout
                  .deleteCookies("JSESSIONID")
                  .invalidateHttpSession(false)
                  .logoutUrl("/custom-logout2")
                  .logoutSuccessUrl("/");
            })
        .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).disable());
    return http.build();
  }

  @GetMapping("/user")
  public Map<String, Object> user(@AuthenticationPrincipal Object principal) {

    logger.info("principal");
    logger.info(principal.toString());
    return Collections.singletonMap("name", principal.toString());
  }

  @PostMapping("/custom-logout5")
  public void customLogout(Object any) {

    logger.info("custom-logout5");
    logger.info(any.toString());
  }

  public static void main(String[] args) {
    SpringApplication.run(SingleSignOnApplication.class, args);
  }
}
