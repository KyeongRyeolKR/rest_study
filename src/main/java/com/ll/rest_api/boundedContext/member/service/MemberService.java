package com.ll.rest_api.boundedContext.member.service;

import com.ll.rest_api.base.jwt.JwtProvider;
import com.ll.rest_api.base.rsData.RsData;
import com.ll.rest_api.boundedContext.member.entity.Member;
import com.ll.rest_api.boundedContext.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public Member join(String username, String password, String email) {
        Member member = Member.builder()
                .username(username)
                .password(password)
                .email(email)
                .build();

        memberRepository.save(member);

        return member;
    }

    public Optional<Member> findByUsername(String username) {
        return memberRepository.findByUsername(username);
    }

    public String genAccessToken(Member member) {
        return jwtProvider.genToken(member.toClaims(), 60 * 60 * 24 * 365);
    }

    public Optional<Member> findById(Long id) {
        return memberRepository.findById(id);
    }

    public RsData canGenAccessToken(Member member, String password) {
        if (!passwordEncoder.matches(password, member.getPassword())) {
            return RsData.of("F-1", "비밀번호가 일치하지 않습니다.");
        }

        return RsData.of("S-1", "엑세스 토큰을 생성할 수 있습니다.");
    }
}