"use client";
import { createBrowserClient } from "@supabase/ssr";

const supabase = createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export function SendCredits({ me, to }: { me: string; to: string }) {
  return <button onClick={() => supabase.rpc("transfer_credits", { from_user: me, to_user: to, amount: 10 })}>Send 10 credits</button>;
}
