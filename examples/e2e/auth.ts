export interface AuthEnvironment {
  authBase: string;
  mailpitBase: string;
}

export interface Credentials {
  login: string;
  email: string;
  password: string;
}

export interface TestUser extends Credentials {
  id: string;
  token: string;
}

export interface AuthSession {
  token: string;
  csrf: string;
}

export const adminCredentials: Credentials = {
  login: 'admin',
  email: 'admin@example.test',
  password: 'Adm1n!Passw0rd123',
};

async function json<T>(url: string, init: RequestInit, expected: number | number[]): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  });
  const body = await response.text();
  const statuses = Array.isArray(expected) ? expected : [expected];
  if (!statuses.includes(response.status)) {
    throw new Error(`${init.method ?? 'GET'} ${url} returned ${response.status}: ${body}`);
  }
  return (body === '' ? undefined : JSON.parse(body)) as T;
}

type MailMessage = { ID: string; To: Array<{ Address: string }> };

async function messageIDs(mailpitBase: string): Promise<Set<string>> {
  const response = await fetch(`${mailpitBase}/api/v1/messages?limit=50`);
  if (!response.ok) throw new Error(`Mailpit message snapshot returned ${response.status}`);
  const payload = await response.json() as { messages?: MailMessage[] };
  return new Set((payload.messages ?? []).map((message) => message.ID));
}

async function waitForOTP(mailpitBase: string, email: string, seen: Set<string>): Promise<string> {
  for (let attempt = 0; attempt < 80; attempt++) {
    const list = await fetch(`${mailpitBase}/api/v1/messages?limit=50`);
    if (list.ok) {
      const payload = await list.json() as {
        messages?: MailMessage[];
      };
      const message = payload.messages?.find((item) =>
        !seen.has(item.ID) &&
        item.To.some((recipient) => recipient.Address.toLowerCase() === email.toLowerCase()));
      if (message) {
        const detail = await fetch(`${mailpitBase}/api/v1/message/${message.ID}`);
        if (detail.ok) {
          const content = await detail.json() as { Text?: string };
          const match = content.Text?.match(/\b(\d{6})\b/);
          if (match) return match[1];
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 125));
  }
  throw new Error(`OTP email for ${email} did not arrive`);
}

export async function loginSession(environment: AuthEnvironment, credentials: Credentials): Promise<AuthSession> {
  const seen = await messageIDs(environment.mailpitBase);
  const challenge = await json<{ login_challenge: string }>(`${environment.authBase}/v1/auth/login`, {
    method: 'POST',
    body: JSON.stringify({ login: credentials.login, password: credentials.password }),
  }, 200);
  const code = await waitForOTP(environment.mailpitBase, credentials.email, seen);
  const tokens = await json<{ access_token: string; csrf_token: string }>(`${environment.authBase}/v1/auth/login/verify-otp`, {
    method: 'POST',
    body: JSON.stringify({
      challenge: challenge.login_challenge,
      code,
      device_id: crypto.randomUUID(),
      device_label: 'examples-playwright',
    }),
  }, 200);
  return { token: tokens.access_token, csrf: tokens.csrf_token };
}

export async function login(environment: AuthEnvironment, credentials: Credentials): Promise<string> {
  return (await loginSession(environment, credentials)).token;
}

function mutationHeaders(session: AuthSession): Record<string, string> {
  return {
    Authorization: `Bearer ${session.token}`,
    'X-CSRF-Token': session.csrf,
    Cookie: `csrf_token=${session.csrf}`,
  };
}

export async function createUser(
  environment: AuthEnvironment,
  admin: AuthSession,
  credentials: Credentials,
): Promise<TestUser> {
  const invite = await json<{ token: string }>(`${environment.authBase}/v1/admin/registration-invites`, {
    method: 'POST',
    headers: mutationHeaders(admin),
    body: JSON.stringify({ email: credentials.email, ttl_seconds: 3600, superuser: false }),
  }, 201);
  const registered = await json<{ user_id: string }>(`${environment.authBase}/v1/auth/register`, {
    method: 'POST',
    body: JSON.stringify({ invite_token: invite.token, ...credentials }),
  }, 201);
  return { ...credentials, id: registered.user_id, token: await login(environment, credentials) };
}

export async function createRole(environment: AuthEnvironment, admin: AuthSession, name: string): Promise<string> {
  const created = await json<{ role_id: string }>(`${environment.authBase}/v1/roles`, {
    method: 'POST',
    headers: mutationHeaders(admin),
    body: JSON.stringify({ name, description: `Playwright role ${name}`, parent_id: '' }),
  }, 201);
  return created.role_id;
}

export async function assignRole(
  environment: AuthEnvironment,
  admin: AuthSession,
  roleID: string,
  userID: string,
  level: 'direct_member' | 'member' | 'role_admin' = 'member',
  tags?: string[],
): Promise<void> {
  await json<void>(`${environment.authBase}/v1/roles/${roleID}/members`, {
    method: 'POST',
    headers: mutationHeaders(admin),
    body: JSON.stringify({ user_id: userID, level, valid_until: null, ...(tags ? { tag_grants: tags } : {}) }),
  }, 204);
}
