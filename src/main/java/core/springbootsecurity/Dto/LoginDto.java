package core.springbootsecurity.Dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class LoginDto {
    private String username;
    private String password;
}
