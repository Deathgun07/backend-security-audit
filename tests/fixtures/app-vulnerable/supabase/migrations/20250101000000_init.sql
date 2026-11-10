create table public.profiles (
  id uuid primary key references auth.users,
  full_name text,
  role text not null default 'user',
  credits int not null default 0
);
alter table public.profiles enable row level security;
create policy "profil modifiable" on public.profiles for update using (true);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  amount int
);

create table public.comments (id bigint generated always as identity primary key, body text);
alter table public.comments enable row level security;
create policy "commentaires" on public.comments for insert to anon with check (true);

create function public.add_credits(uid uuid, n int) returns void
language sql security definer as $$
  update public.profiles set credits = credits + n where id = uid
$$;

create view public.invoice_totals as select user_id, sum(amount) from public.invoices group by 1;
