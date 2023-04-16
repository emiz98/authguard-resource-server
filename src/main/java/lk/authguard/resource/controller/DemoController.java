package lk.authguard.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @PreAuthorize("hasAuthority('read')")
    @GetMapping("/demo")
    public String demo(Authentication a) {
        return "Demo!";
    }
}