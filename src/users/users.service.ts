import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { hash } from 'bcryptjs';
import { User } from './schema/user.schema';
import { FilterQuery, Model, UpdateQuery } from 'mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import { UserResponseDto } from './dto/user-response.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  // This method will create a new user and return the user object/document
  async create(data: CreateUserDto): Promise<UserResponseDto> {
    const newUser = new this.userModel({
      ...data,
      password: await hash(data.password, 10),
    });
    const savedUser = await newUser.save();
    // return savedUser;
    // Map user document to UserResponseDto
    return new UserResponseDto({
      id: savedUser._id.toString(),
      email: savedUser.email,
    });
  }

  // This method will get a user by a query and return the user object/document
  async getUser(query: FilterQuery<User>): Promise<UserResponseDto> {
    const user = await this.userModel.findOne(query);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return new UserResponseDto({
      id: user._id.toString(),
      email: user.email,
    });
  }

  // This method will get all users and return the users object/document
  async getUsers(): Promise<UserResponseDto[]> {
    const users = await this.userModel.find({}).lean();
    return users.map(
      (user) =>
        new UserResponseDto({
          id: user._id.toString(),
          email: user.email,
        }),
    );
  }

  // This method will update a user by a query and return the updated user object/document
  async updateUser(query: FilterQuery<User>, data: UpdateQuery<User>) {
    return this.userModel.findOneAndUpdate(query, data);
  }

  // This method will get a user by email and return the user object/document
  async getOrCreateUser(data: CreateUserDto) {
    const user = await this.userModel.findOne({ email: data.email });
    if (user) {
      return user;
    }
    return this.create(data);
  }

  // This method is specifically for authentication
  async getUserWithPassword(query: FilterQuery<User>): Promise<User> {
    const user = await this.userModel.findOne(query);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }
}
