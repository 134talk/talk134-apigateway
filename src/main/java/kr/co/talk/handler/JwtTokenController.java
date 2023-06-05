package kr.co.talk.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import kr.co.talk.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class JwtTokenController {

    @Autowired
    JwtTokenProvider jwtTokenProvider;
    
    @GetMapping("/getToken/{userId}")
    public String getToken(@PathVariable(value = "userId") String userId) {
        return jwtTokenProvider.createAccessToken(userId);
    }
}
