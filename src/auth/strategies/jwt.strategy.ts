import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { TokenPayload } from '../token-payload.interface';
import { UsersService } from '../../users/users.service';
import { Injectable } from '@nestjs/common';

// JWT Strategy is for Token Validation
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      // Extract JWT from the Authentication cookie in the request.
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => request.cookies?.Authentication,
      ]),
      // The secret key used to verify the JWT signature.
      secretOrKey: configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
    });
  }

  // Verify that the user's token is valid.
  // The payload is the decoded JWT payload extracted by the strategy automatically during initialization.
  async validate(payload: TokenPayload) {
    // Validate and retrieve the user by the payload's userId.
    // If the user is not found, it will throw an error automatically.
    // If the user is found, it will return the user object and attach it to the request object.
    return this.usersService.getUser({ _id: payload.userId });
  }
}
