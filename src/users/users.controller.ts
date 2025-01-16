import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { UserResponseDto } from './dto/user-response.dto';
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async createUser(@Body() request: CreateUserDto): Promise<UserResponseDto> {
    const user = await this.usersService.create(request);
    return user;
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getUsers(): Promise<UserResponseDto[]> {
    return this.usersService.getUsers();
  }
}
