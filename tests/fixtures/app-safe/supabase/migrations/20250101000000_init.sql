create table public.notes (id uuid primary key, owner uuid not null references auth.users, body text);
alter table public.notes enable row level security;
-- This function used to be SECURITY DEFINER and never set search_path: replaced by an invoker function.
create function public.my_notes() returns setof public.notes language sql security invoker as $$
  select * from public.notes where owner = (select auth.uid())
$$;
