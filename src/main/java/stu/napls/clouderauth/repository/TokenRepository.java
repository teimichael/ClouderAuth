package stu.napls.clouderauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import stu.napls.clouderauth.model.Token;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Token findByContent(String content);
}
