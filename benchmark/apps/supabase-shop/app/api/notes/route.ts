import { z } from "zod";
import { createClient } from "@/lib/supabase/server";

const Note = z.object({ body: z.string().min(1).max(5000) });

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { body } = Note.parse(await req.json());
  const { data, error } = await supabase.from("notes").insert({ body }).select().single();
  if (error) return new Response("Error", { status: 500 });
  return Response.json(data);
}
