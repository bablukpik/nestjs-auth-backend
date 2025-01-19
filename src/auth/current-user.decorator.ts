import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '../users/schema/user.schema';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): User => {
    const req = ctx.switchToHttp().getRequest();
    return req.user; // extract user from request like const user = req.user and returns the user object
  },
);

// Uses
// @CurrentUser() user: User
