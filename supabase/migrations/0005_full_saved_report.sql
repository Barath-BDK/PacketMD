-- Lets a saved investigation reopen in full. Holds no packet rows or bytes, and addresses are replaced with labels.
alter table public.reports add column full_report jsonb check (pg_column_size(full_report) < 3000000);
