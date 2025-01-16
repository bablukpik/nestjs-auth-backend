import { Exclude, Expose } from 'class-transformer';
import { IsEmail, IsString } from 'class-validator';

@Expose() // Only expose the properties defined in this DTO
export class UserResponseDto {
  @Expose()
  @IsString()
  id: string;

  @Expose()
  @IsEmail()
  email: string;

  @Exclude()
  password: string;

  @Expose()
  refreshToken?: string;

  constructor(partial: Partial<Omit<UserResponseDto, 'password'>>) {
    Object.assign(this, partial);
  }
}

// A constructor is added to make it easier to map a User document or object into the UserResponseDto
// Example:
/*
const savedUser = new UserResponseDto({
  id: user._id.toHexString(),
  email: user.email,
});
return savedUser;
*/
