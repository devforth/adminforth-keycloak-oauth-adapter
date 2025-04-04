import type { OAuth2Adapter } from "adminforth";
import { jwtDecode } from "jwt-decode";

export default class AdminForthAdapterKeycloakOauth2 implements OAuth2Adapter {
    private clientID: string;
    private clientSecret: string;
    private keycloakUrl: string;
    private realm: string;
    private useOpenID: boolean;
    private name: string;
    private buttonIcon: string | undefined;

    constructor(options: {
      clientID: string;
      clientSecret: string;
      keycloakUrl: string;
      realm: string;
      useOpenID?: boolean;
      name?: string;
      buttonIcon?: string;
    }) {
      if (!options.clientID) {
        throw new Error("AdminForthAdapterKeycloakOauth2: Missing required 'clientID'");
      }
    
      if (!options.clientSecret) {
        throw new Error("AdminForthAdapterKeycloakOauth2: Missing required 'clientSecret'");
      }
    
      if (!options.keycloakUrl) {
        throw new Error("AdminForthAdapterKeycloakOauth2: Missing required 'keycloakUrl'");
      }
    
      if (!options.realm) {
        throw new Error("AdminForthAdapterKeycloakOauth2: Missing required 'realm'");
      }
      try {
        new URL(options.keycloakUrl);
      } catch {
        throw new Error("AdminForthAdapterKeycloakOauth2: 'keycloakUrl' must be a valid URL");
      }

      this.clientID = options.clientID;
      this.clientSecret = options.clientSecret;
      this.keycloakUrl = options.keycloakUrl;
      this.realm = options.realm;
      this.useOpenID = options.useOpenID ?? true;
      this.name = options.name ?? "Keycloak";
      this.buttonIcon = options.buttonIcon;
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
    getName(): string {
      return this.name;
    }
    getIcon(): string {
      return this.buttonIcon || `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 167 151" fill="none">
<g clip-path="url(#clip0_161_14)">
<path d="M21.9018 37.3017L43.5054 0.0132916L130.505 0.00195312L151.992 37.6608L152.018 112.993L130.509 150.63L43.5356 150.66L21.6826 112.997L21.9018 37.3017Z" fill="#4D4D4D"/>
<path d="M21.6867 112.986H60.8951L39.3596 75.0362L56.8737 37.3093L21.9059 37.3018L0 75.3423" fill="#EDEDED"/>
<path d="M72.7853 112.986H101.445L126.787 76.049L101.887 37.6646H68.1744L47.8672 74.7564L72.7853 112.986Z" fill="#E0E0E0"/>
<path d="M0 75.3384L21.6867 112.997H60.8989L39.5977 75.4669L0 75.3384Z" fill="#ACACAC"/>
<path d="M48.2793 75.3462L72.7893 112.997H101.445L126.39 75.3613L48.2793 75.3462Z" fill="#9E9E9E"/>
<path d="M57.9846 75.365L50.5881 77.5193L43.4902 75.3612L72.4676 25.1318L79.7166 37.6722" fill="#00B8E3"/>
<path d="M79.6868 112.986L72.4756 125.579L53.2267 104.841L43.4756 75.3725V75.3574H57.9813" fill="#33C6E9"/>
<path d="M43.4939 75.361H43.4788V75.3723L36.2335 87.9278L28.958 75.429L36.3356 62.6317L57.9845 25.1392H72.475" fill="#008AAA"/>
<path d="M123.227 112.986H167.114L167.088 37.6606H123.227V112.986Z" fill="#D4D4D4"/>
<path d="M123.227 75.4634V112.994H167.035V75.4634H123.227Z" fill="#919191"/>
<path d="M72.4834 125.594H57.9815L36.2344 87.9244L43.4797 75.3765L72.4834 125.594Z" fill="#00B8E3"/>
<path d="M130.464 75.3611L101.479 125.583C98.8146 121.667 94.249 112.997 94.249 112.997L115.992 75.3535L130.464 75.3611Z" fill="#008AAA"/>
<path d="M115.954 125.583L101.479 125.579L130.468 75.3573L137.709 62.817L144.973 75.4405M130.464 75.3611H115.996L94.2451 37.6683L101.445 25.1431L119.05 47.5252L130.464 75.3611Z" fill="#00B8E3"/>
<path d="M137.71 62.8096V62.8209L130.464 75.3612L101.449 25.147L115.966 25.1545L137.71 62.8096Z" fill="#33C6E9"/>
</g>
<defs>
<clipPath id="clip0_161_14">
<rect width="167" height="151" fill="white"/>
</clipPath>
</defs>
</svg>`;
    }
}
