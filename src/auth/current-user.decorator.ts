import { createParamDecorator, ExecutionContext } from '@nestjs/common';

const getCurrentUserByContext = (context: ExecutionContext) =>
  context.switchToHttp().getRequest().user; // const user = req.user;

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext) =>
    getCurrentUserByContext(context), // returns user object
);

// Uses
// @CurrentUser() user: User
