import crypto from "node:crypto";
import { serverEnv } from "@cap/env";
import { eq } from "drizzle-orm";
import type { NextAuthOptions } from "next-auth";
import { getServerSession as _getServerSession } from "next-auth";
import type { Adapter } from "next-auth/adapters";
import EmailProvider from "next-auth/providers/email";
import GoogleProvider from "next-auth/providers/google";
import type { Provider } from "next-auth/providers/index";
import WorkOSProvider from "next-auth/providers/workos";
import { sendEmail } from "../emails/config.ts";
import { db } from "../index.ts";
import { users, organizationInvites, organizationMembers } from "../schema.ts";
import { isEmailAllowedForSignup } from "./domain-utils.ts";
import { DrizzleAdapter } from "./drizzle-adapter.ts";

export const maxDuration = 120;

// ✅ emails permitidos siempre
const INVITE_ONLY_ALLOWED_EMAILS = new Set(
  ["gustavo.toledo@gmail.com", "johannaosoriolizarazo@gmail.com"].map((e) =>
    e.toLowerCase(),
  ),
);

export const authOptions = (): NextAuthOptions => {
  let _adapter: Adapter | undefined;
  let _providers: Provider[] | undefined;

  return {
    get adapter() {
      if (_adapter) return _adapter;
      _adapter = DrizzleAdapter(db());
      return _adapter;
    },
    debug: true,
    session: {
      strategy: "jwt",
    },
    get secret() {
      return serverEnv().NEXTAUTH_SECRET;
    },
    pages: {
      signIn: "/login",
    },
    get providers() {
      if (_providers) return _providers;
      _providers = [
        GoogleProvider({
          clientId: serverEnv().GOOGLE_CLIENT_ID!,
          clientSecret: serverEnv().GOOGLE_CLIENT_SECRET!,
          authorization: {
            params: {
              scope: [
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
              ].join(" "),
              prompt: "select_account",
            },
          },
        }),
        WorkOSProvider({
          clientId: serverEnv().WORKOS_CLIENT_ID as string,
          clientSecret: serverEnv().WORKOS_API_KEY as string,
          profile(profile) {
            return {
              id: profile.id,
              name: profile.first_name
                ? `${profile.first_name} ${profile.last_name || ""}`
                : profile.email?.split("@")[0] || profile.id,
              email: profile.email,
              image: profile.profile_picture_url,
            };
          },
        }),
        EmailProvider({
          async generateVerificationToken() {
            return crypto.randomInt(100000, 1000000).toString();
          },
          async sendVerificationRequest({ identifier, token }) {
            console.log("sendVerificationRequest");

            if (!serverEnv().RESEND_API_KEY) {
              console.log("\n");
              console.log(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
              );
              console.log("🔐 VERIFICATION CODE (Development Mode)");
              console.log(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
              );
              console.log(`📧 Email: ${identifier}`);
              console.log(`🔢 Code: ${token}`);
              console.log(`⏱  Expires in: 10 minutes`);
              console.log(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
              );
              console.log("\n");
            } else {
              console.log({ identifier, token });
              const { OTPEmail } = await import("../emails/otp-email");
              const email = OTPEmail({ code: token, email: identifier });
              console.log({ email });
              await sendEmail({
                email: identifier,
                subject: `Your Cap Verification Code`,
                react: email,
              });
            }
          },
        }),
      ];

      return _providers;
    },
    cookies: {
      sessionToken: {
        name: `next-auth.session-token`,
        options: {
          httpOnly: true,
          sameSite: "none",
          path: "/",
          secure: true,
        },
      },
    },
    callbacks: {
      async signIn({ user, email, credentials }) {
        // 1) Resolver email
        const userEmail =
          user?.email ||
          (typeof email === "string"
            ? email
            : typeof credentials?.email === "string"
              ? credentials.email
              : null);

        // Si no hay email, bloquear
        if (!userEmail || typeof userEmail !== "string") return false;

        // Normalizar email
        const normalizedEmail = userEmail.toLowerCase().trim();

        // 2) Whitelist fija: siempre puede entrar
        if (INVITE_ONLY_ALLOWED_EMAILS.has(normalizedEmail)) return true;

        // 3) Si el usuario ya existe, permitir SOLO si es miembro de alguna org
        const [existingUser] = await db()
          .select({ id: users.id })
          .from(users)
          .where(eq(users.email, normalizedEmail))
          .limit(1);

        if (existingUser?.id) {
          const member = await db()
            .select({ id: organizationMembers.id })
            .from(organizationMembers)
            .where(eq(organizationMembers.userId, existingUser.id))
            .limit(1);

          if (member.length > 0) return true;
        }

        // 4) Si no es miembro (o todavía no existe), permitir SOLO si tiene invitación (a cualquier org)
        const invite = await db()
          .select({ id: organizationInvites.id })
          .from(organizationInvites)
          .where(eq(organizationInvites.email, normalizedEmail))
          .limit(1);

        if (invite.length > 0) return true;

        // 5) Invite-only estricto: bloquear todo lo demás
        console.warn(`Signup blocked (invite-only): ${normalizedEmail}`);
        return false;
      },

      async session({ token, session }) {
        if (!session.user) return session;

        if (token && token.id && typeof token.id === "string") {
          (session.user as { id: string }).id = token.id;
          session.user.name = token.name ?? null;
          session.user.email = token.email ?? null;
          session.user.image = token.picture ?? null;
        }

        return session;
      },

      async jwt({ token, user }) {
        const [dbUser] = await db()
          .select()
          .from(users)
          .where(eq(users.email, token.email || ""))
          .limit(1);

        if (!dbUser) {
          if (user) {
            token.id = user?.id;
          }
          return token;
        }

        return {
          id: dbUser.id,
          name: dbUser.name,
          lastName: dbUser.lastName,
          email: dbUser.email,
          picture: dbUser.image,
        };
      },
    },
  };
};

export const getServerSession = () => _getServerSession(authOptions());
