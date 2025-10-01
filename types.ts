

export enum Role {
  FREE = 'free',
  PRO = 'pro',
  PREMIUM = 'premium',
  MODEL = 'model',
  ADMIN = 'admin',
}

export type RoleSystemInstructions = Record<Role.FREE | Role.PRO | Role.PREMIUM | Role.ADMIN, string>;

export interface Part {
  text: string;
}

export interface Message {
  // FIX: Added Role.ADMIN to the type union to allow admin users to send messages.
  role: Role.FREE | Role.PRO | Role.PREMIUM | Role.ADMIN | Role.MODEL;
  parts: Part[];
  image?: {
    data: string; // base64 encoded string
    mimeType: string;
  }
}

// Full user object, including sensitive info. NEVER expose to frontend.
export interface User {
  id: string;
  username: string; // unique name
  email: string; // unique email
  passwordHash: string;
  isEmailVerified: boolean;
  emailVerificationToken: string | null;
  recoveryEmail?: string;
  recoveryPhone?: string;
  role: Role.FREE | Role.PRO | Role.PREMIUM | Role.ADMIN;
  passwordResetToken?: string | null;
  passwordResetExpires?: number | null;
}

// Safe user object to use in the frontend.
export type PublicUser = Omit<User, 'passwordHash' | 'isEmailVerified' | 'emailVerificationToken' | 'recoveryEmail' | 'recoveryPhone' | 'passwordResetToken' | 'passwordResetExpires'>;

export interface Conversation {
  id:string;
  userId: string;
  title: string;
  messages: Message[];
  createdAt: number;
}