package stu.napls.clouderauth.model;

import lombok.Data;
import stu.napls.clouderauth.core.dictionary.StatusCode;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "auth_token")
@Data
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "content", unique = true)
    private String content;

    @Column(name = "issuingDate")
    private Date issuingDate;

    @Column(name = "expiryDate")
    private Date expiryDate;

    @Column(name = "status", columnDefinition = "integer default " + StatusCode.NORMAL)
    private int status;

}
