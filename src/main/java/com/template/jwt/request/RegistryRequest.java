package com.template.jwt.request;

import com.template.jwt.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class RegistryRequest {

    private String username;
    private String password;
    private Integer age;
    private Role role;
}
