package com.ll.rest_api.boundedContext.member.controller;

import com.ll.rest_api.base.rsData.RsData;
import com.ll.rest_api.boundedContext.member.entity.Member;
import com.ll.rest_api.boundedContext.member.service.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import static org.springframework.util.MimeTypeUtils.ALL_VALUE;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
@RestController
@RequestMapping(value = "api/v1/member", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
@Tag(name = "ApiV1MemberController", description = "로그인 기능과 로그인 된 회원의 정보를 제공 기능을 담당")
public class ApiV1MemberController {

    private final MemberService memberService;

    @Data
    public static class LoginRequest {
        @NotBlank
        private String username;
        @NotBlank
        private String password;
    }


    @RequiredArgsConstructor
    @Data
    public static class LoginResponse {
        private final String accessToken;
    }

    @PostMapping("/login")
    @Operation(summary = "로그인, 엑세스 토큰 발급")
    public RsData<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        Member member = memberService
                .findByUsername(loginRequest.getUsername())
                .orElse(null);

        if (member == null) return RsData.of("F-1", "존재하지 않는 회원입니다.");

        RsData rsData = memberService.canGenAccessToken(member, loginRequest.getPassword());

        if (rsData.isFail()) return rsData;

        String accessToken = memberService.genAccessToken(member);

        return RsData.of(
                "S-1",
                "엑세스 토큰이 생성되었습니다.",
                new LoginResponse(accessToken)
        );
    }

    @RequiredArgsConstructor
    @Data
    public static class MeResponse {
        private final Member member;
    }

    @GetMapping(value = "/me", consumes = ALL_VALUE)
    @Operation(summary = "로그인된 사용자 정보", security = @SecurityRequirement(name = "bearerAuth"))
    public RsData<MeResponse> me(@AuthenticationPrincipal User user) {
        Member member = memberService.findByUsername(user.getUsername()).get();

        return RsData.of(
                "S-1",
                "성공",
                new MeResponse(member)
        );
    }
}
