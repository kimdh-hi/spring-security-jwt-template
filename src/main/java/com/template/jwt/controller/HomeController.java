package com.template.jwt.controller;

import com.template.jwt.config.CustomUserDetailsService;
import com.template.jwt.domain.User;
import com.template.jwt.repository.UserRepository;
import com.template.jwt.request.RegistryRequest;
import com.template.jwt.util.JwtUtil;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.jaxb.SpringDataJaxb;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RequiredArgsConstructor
@RestController
public class HomeController {

    private final UserRepository userRepository;
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager; // authenticate 메서드 : username, password 기반 인증 수행
    private final PasswordEncoder passwordEncoder;
    @GetMapping("/home")
    public String home() {
        return "home";
    }

    /**
     * 회원가입
     */
    @PostMapping("/join")
    public ResponseEntity<Long> join(@RequestBody RegistryRequest request) {
        User savedUser
                = userRepository.save(new User(request.getUsername(), passwordEncoder.encode(request.getPassword()), request.getAge(), request.getRole()));
        log.info("savedUser.username = {} ", savedUser.getUsername());
        log.info("savedUser.password = {} ", savedUser.getPassword());
        log.info("savedUser.age = {} ", savedUser.getAge());
        log.info("savedUser.role = {} ", savedUser.getRole());

        return ResponseEntity.ok(savedUser.getId());
    }

    /**
     * 인증요청
     */
    @PostMapping("/auth")
    public ResponseEntity<LoginSuccessResponse> authenticateTest(
            @RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        log.info("/auth 호출");
        try {
            // username, password 인증 시도
            log.info("loginRequest.username = {}", loginRequest.getUsername());
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            UserDetails principal = (UserDetails) authenticate.getPrincipal();
            log.info("principal.username = {}", principal.getUsername());
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("로그인 실패");
        }
        // 인증 성공 후 인증된 user의 정보를 갖고옴
        log.info("/auth username = {}", loginRequest.getUsername());
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.username);
        // subject, claim 모두 UserDetails를 사용하므로 객체를 그대로 전달
        String token = jwtUtil.generateToken(userDetails);
        // 생성된 토큰을 헤더에 세팅하여 클라이언트에게 응답
        response.addHeader("Authorization", "Bearer " + token);

        // 생성된 토큰을 응답 (Test)
        return ResponseEntity.ok(new LoginSuccessResponse(token));
    }

    @AllArgsConstructor
    @Data
    static class LoginRequest{
        private String username;
        private String password;
    }

    @AllArgsConstructor
    @Data
    static class LoginSuccessResponse {
        private String token;
    }
}
