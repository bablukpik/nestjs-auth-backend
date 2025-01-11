import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

// Local Strategy with User Lookup
// By default this Strategy's name is local
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      usernameField: 'email', // Overwrite the local strategy's username field
    });
  }

  // Verify that the user's credentials are valid.
  async validate(email: string, password: string) {
    return this.authService.verifyUser(email, password); // returns user object if valid and sets it to req.user
  }
}

// Notes:
// Each strategy has a respective guard
// LocalStrategy -> LocalAuthGuard
// JwtStrategy -> JwtAuthGuard

// Guards are used to protect routes
