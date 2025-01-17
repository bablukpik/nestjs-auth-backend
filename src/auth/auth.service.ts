import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcryptjs';
import { User } from '../users/schema/user.schema';
import { UsersService } from '../users/users.service';
import { Response } from 'express';
import { TokenPayload } from './token-payload.interface';
import { UserResponseDto } from '../users/dto/user-response.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async setCurrentRefreshToken(refreshToken: string, userId: string) {
    const hashedRefreshToken = await hash(refreshToken, 10);
    await this.usersService.updateUser(
      { _id: userId },
      {
        refreshToken: hashedRefreshToken,
      },
    );
  }

  async login(user: User, response: Response, isGoogleAuth = false) {
    const tokenPayload: TokenPayload = {
      userId: user._id.toString(),
    };

    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: parseInt(
        this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS'),
      ),
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: parseInt(
        this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS'),
      ),
    });

    await this.setCurrentRefreshToken(refreshToken, user._id.toString());

    response.cookie('Authentication', accessToken, {
      httpOnly: true,
      path: '/',
      maxAge: parseInt(
        this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS'),
      ),
      secure: this.configService.get('NODE_ENV') === 'production',
    });

    response.cookie('Refresh', refreshToken, {
      httpOnly: true,
      path: '/',
      maxAge: parseInt(
        this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS'),
      ),
      secure: this.configService.get('NODE_ENV') === 'production',
    });

    if (isGoogleAuth) {
      response.redirect(this.configService.getOrThrow('AUTH_UI_REDIRECT'));
    }

    return new UserResponseDto({
      id: user._id.toString(),
      email: user.email,
    });
  }

  async verifyUser(email: string, password: string) {
    try {
      const user = await this.usersService.getUserWithPassword({
        email,
      });
      const passwordIsValid = await compare(password, user.password);
      if (!passwordIsValid) {
        throw new UnauthorizedException('Invalid credentials');
      }
      return user;
    } catch (err) {
      throw new UnauthorizedException('Credentials are not valid.');
    }
  }

  async verifyUserRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUser({ _id: userId });
      const authenticated = await compare(refreshToken, user.refreshToken);
      if (!authenticated) {
        throw new UnauthorizedException();
      }
      return user;
    } catch (err) {
      throw new UnauthorizedException('Refresh token is not valid.');
    }
  }
}
