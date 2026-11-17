create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text,
  role text not null default 'customer',
  credits integer not null default 0
);
alter table public.profiles enable row level security;
create policy "read own profile" on public.profiles for select to authenticated using ((select auth.uid()) = id);
create policy "update own profile" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.notes (
  id bigint generated always as identity primary key,
  owner uuid not null references auth.users default auth.uid(),
  body text not null check (length(body) < 5000)
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated
  using ((select auth.uid()) = owner) with check ((select auth.uid()) = owner);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references auth.users,
  total_cents integer not null,
  status text not null default 'pending',
  shipping_address text
);

create table public.messages (
  id bigint generated always as identity primary key,
  sender uuid not null references auth.users default auth.uid(),
  recipient uuid not null references auth.users,
  body text not null
);
alter table public.messages enable row level security;
create policy "read messages" on public.messages for select to authenticated using (true);
create policy "send messages" on public.messages for insert to authenticated with check ((select auth.uid()) = sender);

create policy "staff can read all profiles" on public.profiles for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'staff') = 'true');

create function public.transfer_credits(from_user uuid, to_user uuid, amount integer) returns void
language plpgsql security definer as $$
begin
  update public.profiles set credits = credits - amount where id = from_user;
  update public.profiles set credits = credits + amount where id = to_user;
end $$;

create function public.my_notes() returns setof public.notes
language sql security invoker set search_path = '' as $$
  select * from public.notes where owner = (select auth.uid())
$$;

create view public.order_stats with (security_invoker = true) as
  select customer_id, count(*) as orders, sum(total_cents) as spent from public.orders group by 1;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);
