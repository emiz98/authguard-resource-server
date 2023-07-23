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
        return "Read granted!";
    }
    @PreAuthorize("hasAuthority('write')")
    @GetMapping("/demo2")
    public String demo2(Authentication a) {
        return "Write granted!";
    }
}