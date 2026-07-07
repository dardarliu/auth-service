import { NextRequest } from "next/server";
import { db } from "@/lib/db/client";
import { passwordResets, users } from "@/lib/db/schema";
import { eq, and, isNull } from "drizzle-orm";
import { hashToken } from "@/lib/auth/tokens";
import { hashPassword, validatePassword } from "@/lib/auth/password";
import { revokeAllUserSessions } from "@/lib/auth/sessions";
import { sendPasswordChangedEmail } from "@/lib/email/send";
import { json, error } from "@/lib/api/helpers";

export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token");

  if (!token) {
    return renderPage("invalid link", "this reset link is missing or malformed.", false);
  }

  const tokenHash = hashToken(token);
  const reset = await db.query.passwordResets.findFirst({
    where: and(
      eq(passwordResets.tokenHash, tokenHash),
      isNull(passwordResets.usedAt)
    ),
  });

  if (!reset || reset.expiresAt < new Date()) {
    return renderPage("link expired", "this reset link is invalid or has expired. request a new one.", false);
  }

  return renderForm(token);
}

function renderForm(token: string) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Password</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0a;color:#fafafa;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace">
<div style="text-align:center;max-width:320px;padding:2rem;width:100%">
<div id="form-view">
<h1 style="font-size:1.25rem;font-weight:600;margin:0">reset password</h1>
<p style="color:#737373;font-size:0.75rem;margin-top:0.5rem">enter your new password (12+ characters)</p>
<form id="form" style="margin-top:1.5rem">
<input type="hidden" name="token" value="${token}">
<input type="password" name="new_password" placeholder="new password" minlength="12" maxlength="128" required
  style="width:100%;box-sizing:border-box;background:transparent;border:1px solid #333;padding:0.5rem 0.75rem;font-size:0.75rem;color:#fafafa;font-family:inherit;outline:none">
<button type="submit" id="submit-btn"
  style="width:100%;margin-top:0.75rem;padding:0.5rem;font-size:0.75rem;background:transparent;border:1px solid #333;color:#fafafa;cursor:pointer;font-family:inherit">
  reset password</button>
<p id="error" style="color:#f87171;font-size:0.7rem;margin-top:0.75rem;display:none"></p>
</form>
</div>
<div id="success-view" style="display:none">
<h1 style="font-size:1.25rem;font-weight:600;margin:0">password reset</h1>
<p style="color:#737373;font-size:0.75rem;margin-top:0.75rem">your password has been changed. you can now sign in.</p>
</div>
</div>
<script>
document.getElementById('form').addEventListener('submit', async function(e) {
  e.preventDefault();
  var form = document.getElementById('form');
  var tokenVal = form.querySelector('input[name="token"]').value;
  var passwordVal = form.querySelector('input[name="new_password"]').value;
  var errEl = document.getElementById('error');
  var btn = document.getElementById('submit-btn');
  errEl.style.display = 'none';
  btn.disabled = true;
  btn.textContent = 'resetting...';
  try {
    var res = await fetch('/api/v1/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: tokenVal, new_password: passwordVal })
    });
    var data = await res.json();
    if (res.ok) {
      document.getElementById('form-view').style.display = 'none';
      document.getElementById('success-view').style.display = 'block';
    } else {
      errEl.textContent = data.message || 'something went wrong';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'reset password';
    }
  } catch (err) {
    errEl.textContent = 'network error — please try again';
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'reset password';
  }
});
</script>
</body></html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html",
      "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    },
  });
}

function renderPage(title: string, message: string, ok: boolean) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${ok ? "Success" : "Error"}</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0a;color:#fafafa;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace">
<div style="text-align:center;max-width:360px;padding:2rem">
<h1 style="font-size:1.25rem;font-weight:600;margin:0">${title}</h1>
<p style="color:#737373;font-size:0.8rem;margin-top:0.75rem">${message}</p>
</div></body></html>`;

  return new Response(html, {
    status: ok ? 200 : 400,
    headers: { "Content-Type": "text/html" },
  });
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { token, new_password } = body;

  if (!token || !new_password) {
    return error("Token and new_password are required", 400, "validation_error");
  }

  const passwordError = validatePassword(new_password);
  if (passwordError) {
    return error(passwordError, 400, "validation_error");
  }

  const tokenHash = hashToken(token);
  const reset = await db.query.passwordResets.findFirst({
    where: and(
      eq(passwordResets.tokenHash, tokenHash),
      isNull(passwordResets.usedAt)
    ),
  });

  if (!reset || reset.expiresAt < new Date()) {
    return error("Invalid or expired token", 400, "invalid_token");
  }

  const newHash = await hashPassword(new_password);

  // Atomic claim — prevents concurrent use of same token
  const [claimed] = await db
    .update(passwordResets)
    .set({ usedAt: new Date() })
    .where(and(eq(passwordResets.id, reset.id), isNull(passwordResets.usedAt)))
    .returning({ id: passwordResets.id });

  if (!claimed) {
    return error("Invalid or expired token", 400, "invalid_token");
  }

  await db
    .update(users)
    .set({
      passwordHash: newHash,
      passwordChangedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(users.id, reset.userId));

  await revokeAllUserSessions(reset.userId);

  const user = await db.query.users.findFirst({
    where: eq(users.id, reset.userId),
  });
  if (user) {
    await sendPasswordChangedEmail(user.email);
  }

  return json({
    message: "Password reset successfully. Please log in with your new password.",
  });
}
