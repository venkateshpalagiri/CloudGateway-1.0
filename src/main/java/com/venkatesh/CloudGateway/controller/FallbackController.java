package com.venkatesh.CloudGateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FallbackController {
    @GetMapping("/orderServiceFallback")
    public String orderServiceFallback(){
        return "Order Service is down!";
    }
    @GetMapping("/productServiceFallback")
    public String productServiceFallback(){
        return "Product Service is down!";
    }
    @GetMapping("/paymentServiceFallback")
    public String paymentServiceFallback(){
        return "Payment Service is down!";
    }
}
