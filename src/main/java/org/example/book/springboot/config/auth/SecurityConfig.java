package org.example.book.springboot.config.auth;

import lombok.RequiredArgsConstructor;
import org.example.book.springboot.domain.user.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions
                        (HeadersConfigurer.FrameOptionsConfig::disable))
                .authorizeHttpRequests(config -> config.requestMatchers(new AntPathRequestMatcher("/"),
                                                                        new AntPathRequestMatcher("/css/**"),
                                                                        new AntPathRequestMatcher("/images/**"),
                                                                        new AntPathRequestMatcher("/js/**")).permitAll())
                .authorizeHttpRequests(config -> config.requestMatchers(antMatcher("/api/v1/**")).hasRole(Role.USER.name())
                        .anyRequest().authenticated())
                .logout(config -> config.logoutSuccessUrl("/"))
                .oauth2Login(oauthConfig -> oauthConfig
                        .userInfoEndpoint(endPoint->endPoint
                                .userService(customOAuth2UserService)));

        return http.build();
    }
}
