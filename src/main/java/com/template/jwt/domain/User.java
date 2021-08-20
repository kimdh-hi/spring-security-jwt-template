package com.template.jwt.domain;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    @Id @GeneratedValue
    private Long id;

    private String username;

    private String password;

    private Integer age;

    @Enumerated(EnumType.STRING)
    private Role role;

    public User(String username, String password, Integer age, Role role) {
        this.username = username;
        this.password = password;
        this.age = age;
        this.role = role;
    }
}
