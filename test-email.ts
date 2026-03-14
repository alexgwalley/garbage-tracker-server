import 'dotenv/config';
import { Resend } from 'resend';

const apiKey = process.env.RESEND_API_KEY;
console.log('API key present:', !!apiKey);
console.log('API key prefix:', apiKey?.slice(0, 8));

const resend = new Resend(apiKey);

const to = process.argv[2] || 'delivered@resend.dev';
console.log('Sending to:', to);

const result = await resend.emails.send({
    from: 'Garbage Tracker <onboarding@resend.dev>',
    to,
    subject: 'Test email',
    html: '<h1>Hello!</h1><p>This is a test.</p>',
});

console.log('Result:', JSON.stringify(result, null, 2));
