import { Resend } from 'resend';
import { SafeResult } from '../../auth.js';
import { EmailMessage } from '../email.js';

function createClient(): SafeResult<Resend> {
  let value: Resend = new Resend('');
  let error: string | null = null;

  const apiKey = process.env.RESEND_API_KEY;
  const hasKey = apiKey != null && apiKey.length > 0;
  if (!hasKey) {
    error = 'RESEND_API_KEY not set — email sending disabled';
    console.warn(error);
  }

  if (error === null) {
    value = new Resend(apiKey);
  }

  const result: SafeResult<Resend> = { value, error };
  return result;
}

export async function sendEmail(message: EmailMessage): Promise<SafeResult<string>> {
  const clientResult = createClient();

  let value = '';
  let error: string | null = null;

  if (clientResult.error !== null) {
    error = clientResult.error;
    console.log(`[email] Skipped sending to ${message.to}: ${error}`);
  }

  if (clientResult.error === null) {
    try {
      const response = await clientResult.value.emails.send({
        from: 'Pick It Up <noreply@pickitup.dev>',
        to: message.to,
        subject: message.subject,
        html: message.html,
      });
      value = JSON.stringify(response);
      console.log(`[email] Sent to ${message.to}:`, value);
    } catch (err) {
      error = `Email send failed: ${err}`;
      console.error(`[email] Failed to send to ${message.to}:`, error);
    }
  }

  const result: SafeResult<string> = { value, error };
  return result;
}
