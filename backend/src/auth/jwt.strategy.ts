import { Injectable, Optional, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { StrKey } from '@stellar/stellar-sdk';
import { JWT_ALGORITHM, getJwtVerificationSecrets } from '../config/env.config';
import { RefreshTokenStoreService } from './refresh-token-store.service';

export interface JwtPayload {
  address: string;
  sub: string;
  iat: number;
  exp: number;
  sid?: string;
  jti?: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly jwtService: JwtService,
    @Optional() private readonly refreshTokenStore?: RefreshTokenStoreService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrPublicKeyProvider: (_request: any, _rawJwtToken: string, done: any) => {
        const secrets = getJwtVerificationSecrets();
        done(null, secrets);
      },
      algorithms: [JWT_ALGORITHM],
    });
  }

  async validate(payload: JwtPayload) {
    // #846: a malformed wallet claim is an authentication failure (401), not a server error.
    if (typeof payload.address !== 'string' || !StrKey.isValidEd25519PublicKey(payload.address)) {
      throw new UnauthorizedException('Invalid wallet address in token');
    }

    // #847: an access token superseded by a refresh of the same session is no longer valid.
    if (
      payload.sid &&
      payload.jti &&
      this.refreshTokenStore &&
      !(await this.refreshTokenStore.isActiveAccessJti(payload.sid, payload.jti))
    ) {
      throw new UnauthorizedException('Token has been superseded by a refresh');
    }

    return { address: payload.address, sub: payload.sub };
  }
}
