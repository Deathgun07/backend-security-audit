export async function POST(request: Request) {
  const body = await request.json();
  const res = await fetch(body.url);
  return new Response(await res.text());
}
