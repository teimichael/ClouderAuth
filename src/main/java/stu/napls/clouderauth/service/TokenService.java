package stu.napls.clouderauth.service;

import stu.napls.clouderauth.model.Token;

public interface TokenService {
    Token create(Token token);

    Token update(Token token);

    Token findById(long id);

    Token findByContent(String content);
}
