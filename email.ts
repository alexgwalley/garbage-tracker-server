import { Resend } from 'resend';

function getResendClient(): Resend | null {
    const apiKey = process.env.RESEND_API_KEY;
    const hasKey = apiKey != null && apiKey.length > 0;
    if (!hasKey) {
        console.warn('RESEND_API_KEY not set — email sending disabled');
        return null;
    }
    const client = new Resend(apiKey);
    return client;
}

export async function sendVerificationEmail(email: string, code: string): Promise<void> {
    const client = getResendClient();
    const canSend = client != null;
    if (!canSend) {
        console.log(`[email] Would send code ${code} to ${email} (no API key)`);
        return;
    }

    try {
        await client!.emails.send({
            from: 'Garbage Tracker <onboarding@resend.dev>',
            to: email,
            subject: 'Your verification code',
            html: `
                <h2>Welcome to Garbage Tracker!</h2>
                <p>Your verification code is:</p>
                <h1 style="font-size: 36px; letter-spacing: 8px; font-family: monospace;">${code}</h1>
                <p>Enter this code in the app to verify your email.</p>
            `,
        });
        console.log(`[email] Verification email sent to ${email}`);
    } catch (err) {
        console.error(`[email] Failed to send to ${email}:`, err);
    }
}
