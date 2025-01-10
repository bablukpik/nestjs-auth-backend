import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

// Here this guard is made with the local strategy
@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
