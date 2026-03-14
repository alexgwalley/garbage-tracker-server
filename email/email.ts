import { SafeResult } from '../auth.js';
import { sendEmail } from './resend/resend.js';

// --- Generic email interface ---

export interface EmailMessage {
  to: string;
  subject: string;
  html: string;
}

export type SendEmail = (message: EmailMessage) => Promise<SafeResult<string>>;

// --- Public API ---

export { sendEmail };

export async function sendVerificationEmail(email: string, code: string): Promise<SafeResult<string>> {
  const message: EmailMessage = {
    to: email,
    subject: 'Your verification code',
    html: `
      <h2>Welcome to Garbage Tracker!</h2>
      <p>Your verification code is:</p>
      <h1 style="font-size: 36px; letter-spacing: 8px; font-family: monospace;">${code}</h1>
      <p>Enter this code in the app to verify your email.</p>
    `,
  };
  const result = await sendEmail(message);
  return result;
}
