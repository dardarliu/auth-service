import { Resend } from "resend";

const FROM = "Auth <noreply@yourdomain.com>";

function getResend() {
  return new Resend(process.env.RESEND_API_KEY);
}

export async function sendVerificationEmail(email: string, token: string) {
  const url = `${process.env.AUTH_URL}/api/v1/verify-email?token=${token}`;
  await getResend().emails.send({
    from: FROM,
    to: email,
    subject: "Verify your email",
    text: `Click to verify your email: ${url}\n\nThis link expires in 24 hours.`,
  });
}

export async function sendPasswordResetEmail(email: string, token: string) {
  const url = `${process.env.AUTH_URL}/api/v1/reset-password?token=${token}`;
  await getResend().emails.send({
    from: FROM,
    to: email,
    subject: "Reset your password",
    text: `Click to reset your password: ${url}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email.`,
  });
}

export async function sendPasswordChangedEmail(email: string) {
  await getResend().emails.send({
    from: FROM,
    to: email,
    subject: "Your password was changed",
    text: "Your password was just changed. If you didn't do this, contact support immediately.",
  });
}
