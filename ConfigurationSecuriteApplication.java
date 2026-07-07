package com.example.sih_project.securite;

import lombok.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class ConfigurationSecuriteApplication{
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtFilter jwtFilter;
    private final UserDetailsService userDetailsService;
    public ConfigurationSecuriteApplication(BCryptPasswordEncoder bCryptPasswordEncoder, JwtFilter jwtFilter, UserDetailsService userDetailsService) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtFilter = jwtFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return
                httpSecurity
                        .cors(withDefaults())
                        .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests(
                                authorize ->
                                        authorize
                                                .requestMatchers(POST,"/inscription").permitAll()
                                                .requestMatchers(POST,"/activation").permitAll()
                                                .requestMatchers(POST,"/connexion").permitAll()
                                                .requestMatchers("/swagger-ui.html").permitAll()
                                                .requestMatchers("/swagger-ui/**").permitAll()
                                                .requestMatchers("/swagger-resources/**").permitAll()
                                                .requestMatchers("/v2/api-docs").permitAll()
                                                .requestMatchers("/swagger-resources/configuration/ui").permitAll()
                                                .requestMatchers("/swagger-resources/configuration/security").permitAll()
                                                .requestMatchers("/swagger-ui.html/**").permitAll()
                                                .requestMatchers("/webjars/**").permitAll()
                                                .requestMatchers("/auth/**").permitAll()
                                                .requestMatchers("/v2/api-docs/**").permitAll()
                                                .requestMatchers("/v3/api-docs/**").permitAll()
                                                .requestMatchers("/v3/api-docs/swagger-ui.html").permitAll()
                                                .requestMatchers("/v3/api-docs/").permitAll()
                                                .requestMatchers(POST,"centre/creer").permitAll()
                                                .requestMatchers(GET,"centre/lister").permitAll()

                                                .anyRequest().authenticated()
                        )
                        .sessionManagement(httpSecuritySessionManagementConfigurer ->
                                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(STATELESS)

                                )
                        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                        .build();
    }

    @Bean
    public AuthenticationManager authenticationManager (AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider () {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return daoAuthenticationProvider;
    }


//    @Bean
//    public WebMvcConfigurer corsConfigurer() {
//        return new WebMvcConfigurer() {
//            @Override
//            public void addCorsMappings(@NonNull CorsRegistry registry) {
//                registry.addMapping("/**")
//                        .allowedOrigins("http://localhost:8080/api")
//                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
//                        .allowedHeaders("*")
//                        .allowCredentials(true);
//            }
//        };
//    }


}
