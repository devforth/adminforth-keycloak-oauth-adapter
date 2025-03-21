import type { OAuth2Adapter } from "adminforth";
import { jwtDecode } from "jwt-decode";

export default class AdminForthAdapterKeycloakOauth2 implements OAuth2Adapter {
    private clientID: string;
    private clientSecret: string;
    private keycloakUrl: string;
    private realm: string;
    private useOpenID: boolean;

    constructor(options: {
      clientID: string;
      clientSecret: string;
      keycloakUrl: string;
      realm: string;
      useOpenID?: boolean;
    }) {
      this.clientID = options.clientID;
      this.clientSecret = options.clientSecret;
      this.keycloakUrl = options.keycloakUrl;
      this.realm = options.realm;
      this.useOpenID = options.useOpenID ?? process.env.OPENID === "true";
    }
  
    getAuthUrl(): string {
      const params = new URLSearchParams({
        client_id: this.clientID,
        response_type: 'code',
        scope: 'openid email profile',
      });
      return `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/auth?${params.toString()}`;
    }
  
    async getTokenFromCode(code: string, redirect_uri: string): Promise<{ email: string; }> {
      const tokenResponse = await fetch(`${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: this.clientID,
          client_secret: this.clientSecret,
          redirect_uri,
          grant_type: 'authorization_code',
        }),
      });

      const tokenData = await tokenResponse.json();

      if (tokenData.error) {
        console.error('Token error:', tokenData);
        throw new Error(tokenData.error_description || tokenData.error);
      }

      if (this.useOpenID && tokenData.access_token) {
        try {
          const decodedToken: any = jwtDecode(tokenData.access_token);
          if (decodedToken.email) {
            return { email: decodedToken.email };
          }
        } catch (error) {
          console.error("Error decoding token:", error);
        }
      }

      const userInfoResponse = await fetch(`${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/userinfo`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      const userInfo = await userInfoResponse.json();

      if (!userInfo.email) {
        throw new Error("Email not found in user info");
      }

      return { email: userInfo.email };
    }

    getIcon(): string {
      return `<?xml version="1.0" encoding="utf-8"?>
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2m0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8m1-12h-2v5h5v-2h-3z"/></svg>`;
    }
}
