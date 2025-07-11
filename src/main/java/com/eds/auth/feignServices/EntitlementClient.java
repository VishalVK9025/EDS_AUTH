package com.eds.auth.feignServices;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@FeignClient(name = "Entitlement", url = "${eds.app.entitlement}")
public interface EntitlementClient {
    @GetMapping("/user-role/getRolesByUserId")
    List<String> getRolesByUserId(@RequestParam String userId);
}
