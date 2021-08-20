package com.template.jwt.config;

import com.template.jwt.domain.User;
import com.template.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("loadUserByUsername username = {}", username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(()->{ throw new UsernameNotFoundException("찾을 수 없는 username"); });

        log.info("loadUserByUsername find.username = {}", user.getUsername());
        return new SecurityUser(user);
    }
}
