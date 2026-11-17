import { createClient } from "@/lib/supabase/server";
import { admin } from "@/lib/supabase/admin";

export async function GET() {
  const supabase = await createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { data } = await admin.from("orders").select("id, customer_id, total_cents, shipping_address");
  return Response.json(data);
}
