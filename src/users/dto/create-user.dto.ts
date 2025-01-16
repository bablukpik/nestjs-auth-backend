import { IsEmail, IsStrongPassword } from 'class-validator';

// CreateUserDto handles input validation
export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsStrongPassword()
  password: string;
}
