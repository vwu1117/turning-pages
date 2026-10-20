-- Turning Pages: database setup for Supabase.
-- Run once in your project: Dashboard > SQL Editor > New query > paste all of this > Run.
-- Safe to run again.

-- One row per reader's book. Stories, people and settings live in `data`;
-- what the reader practised lives in `progress`, so the tablet and the
-- family's phone can save at the same time without overwriting each other.
create table if not exists public.books (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null default auth.uid() references auth.users (id) on delete cascade,
  reader_name text not null default '',
  data jsonb not null default '{}'::jsonb,
  progress jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Family invited to help write a book, by email.
create table if not exists public.book_members (
  book_id uuid not null references public.books (id) on delete cascade,
  email text not null,
  added_at timestamptz not null default now(),
  primary key (book_id, email)
);

-- The database, not the device, decides when a book last changed.
create or replace function public.tp_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end;
$$;
drop trigger if exists tp_touch on public.books;
create trigger tp_touch before update on public.books for each row execute function public.tp_touch();

-- Who may open a book: its owner, or someone whose sign-in email was invited.
-- (security definer so the policies below don't loop back on themselves)
create or replace function public.tp_owns_book(b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.books where id = b and owner = auth.uid());
$$;

create or replace function public.tp_can_open_book(b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.books where id = b and owner = auth.uid())
      or exists (
        select 1 from public.book_members m
        where m.book_id = b and lower(m.email) = lower(coalesce(auth.jwt() ->> 'email', ''))
      );
$$;

create or replace function public.tp_can_open_folder(f text) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.tp_can_open_book(b.id) from public.books b where b.id::text = f), false);
$$;

alter table public.books enable row level security;
alter table public.book_members enable row level security;

grant select, insert, update, delete on public.books to authenticated;
grant select, insert, delete on public.book_members to authenticated;
revoke all on public.books from anon;
revoke all on public.book_members from anon;

drop policy if exists "books: read" on public.books;
create policy "books: read" on public.books
  for select to authenticated using (public.tp_can_open_book(id));

drop policy if exists "books: create" on public.books;
create policy "books: create" on public.books
  for insert to authenticated with check (owner = auth.uid());

drop policy if exists "books: update" on public.books;
create policy "books: update" on public.books
  for update to authenticated using (public.tp_can_open_book(id)) with check (public.tp_can_open_book(id));

drop policy if exists "books: delete" on public.books;
create policy "books: delete" on public.books
  for delete to authenticated using (owner = auth.uid());

drop policy if exists "members: read" on public.book_members;
create policy "members: read" on public.book_members
  for select to authenticated using (public.tp_can_open_book(book_id));

drop policy if exists "members: add" on public.book_members;
create policy "members: add" on public.book_members
  for insert to authenticated with check (public.tp_owns_book(book_id));

drop policy if exists "members: remove" on public.book_members;
create policy "members: remove" on public.book_members
  for delete to authenticated using (public.tp_owns_book(book_id));

-- Private photo storage. Each photo is saved as photos/<book id>/<photo id>.jpg
-- and is only ever shown through short-lived signed links.
insert into storage.buckets (id, name, public)
values ('photos', 'photos', false)
on conflict (id) do update set public = false;

drop policy if exists "turning pages photos: read" on storage.objects;
create policy "turning pages photos: read" on storage.objects
  for select to authenticated
  using (bucket_id = 'photos' and public.tp_can_open_folder((storage.foldername(name))[1]));

drop policy if exists "turning pages photos: add" on storage.objects;
create policy "turning pages photos: add" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'photos' and public.tp_can_open_folder((storage.foldername(name))[1]));

drop policy if exists "turning pages photos: replace" on storage.objects;
create policy "turning pages photos: replace" on storage.objects
  for update to authenticated
  using (bucket_id = 'photos' and public.tp_can_open_folder((storage.foldername(name))[1]));

drop policy if exists "turning pages photos: remove" on storage.objects;
create policy "turning pages photos: remove" on storage.objects
  for delete to authenticated
  using (bucket_id = 'photos' and public.tp_can_open_folder((storage.foldername(name))[1]));
