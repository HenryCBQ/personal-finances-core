import { BadRequestException, CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { ROLES_KEY } from '@moduleAuth/decorators/roles.decorator';
import { User } from '@moduleAuth/entities/user.entity';

@Injectable()
export class UserRoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const validRoles: string[] = this.reflector.get(ROLES_KEY, context.getHandler());

    if(!validRoles) return true;
    
    const { user } = context.switchToHttp().getRequest<{ user: User }>();
    
    if(!user || !user.role) new BadRequestException("User not found");

    return validRoles.some((role) => user.role === role);
  }
}
