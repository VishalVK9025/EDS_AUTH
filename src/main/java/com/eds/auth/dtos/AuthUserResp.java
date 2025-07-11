package com.eds.auth.dtos;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AuthUserResp {
    private String username;
    private String jwtToken;
    private List<String> roles;
}
