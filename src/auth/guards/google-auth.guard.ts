import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

// For each strategy, we need to create a new guard and the Guard is used to protect routes
// The AuthGuard is a built-in guard that is used to protect routes
// The 'google' is the name of the strategy we are using
@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {}
