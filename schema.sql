-- ================================================================
-- ClearBin — Supabase Schema
-- Run this entire file in: Supabase Dashboard → SQL Editor → New query
--
-- After running:
--   1. Go to Authentication → Users → "Add user" (or "Invite")
--      Create: clearbin12@gmail.com / Clearbin2025!
--      This becomes the admin account.
--   2. Go to Realtime → Tables → enable "notifications" table
--   3. Copy your Project URL + anon key from Project Settings → API
--      and paste them into the SUPABASE_URL / SUPABASE_ANON constants
--      at the top of each HTML file.
-- ================================================================

-- ── TABLES ──────────────────────────────────────────────────────

-- Client profiles (linked to Supabase auth.users)
CREATE TABLE IF NOT EXISTS clients (
  id          UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  first_name  TEXT NOT NULL DEFAULT '',
  last_name   TEXT NOT NULL DEFAULT '',
  phone       TEXT,
  plan        TEXT DEFAULT 'monthly',
  street      TEXT,
  city        TEXT,
  zip         TEXT,
  bins        TEXT[] DEFAULT ARRAY['trash','recycling'],
  status      TEXT DEFAULT 'pending',   -- pending | active | paused | cancelled
  notes       TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Employees (PIN-based, separate from Supabase Auth)
CREATE TABLE IF NOT EXISTS cleaners (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  pin         TEXT NOT NULL,
  active      BOOLEAN DEFAULT TRUE,
  cities      TEXT[] DEFAULT ARRAY[]::TEXT[],
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Individual clean visits
CREATE TABLE IF NOT EXISTS jobs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id       UUID REFERENCES clients(id) ON DELETE SET NULL,
  cleaner_id      UUID REFERENCES cleaners(id) ON DELETE SET NULL,
  scheduled_date  DATE NOT NULL DEFAULT CURRENT_DATE,
  status          TEXT DEFAULT 'pending',  -- pending | on_way | complete | skipped
  eta             TEXT,
  admin_notes     TEXT,
  before_photo    TEXT,
  after_photo     TEXT,
  plan            TEXT,
  bins            TEXT[],
  earnings        NUMERIC(8,2) DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Booking intake queue (before admin approval)
CREATE TABLE IF NOT EXISTS bookings (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  status           TEXT DEFAULT 'pending',  -- pending | approved | declined
  client_id        UUID REFERENCES clients(id) ON DELETE SET NULL,
  first_name       TEXT,
  last_name        TEXT,
  email            TEXT,
  phone            TEXT,
  plan             TEXT,
  street           TEXT,
  city             TEXT,
  zip              TEXT,
  bins             TEXT[],
  start_date       DATE,
  notes            TEXT,
  referral         TEXT,
  assigned_cleaner UUID REFERENCES cleaners(id) ON DELETE SET NULL,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Cross-portal notifications (cleaner → client)
CREATE TABLE IF NOT EXISTS notifications (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type        TEXT NOT NULL,   -- cleaner_on_way | admin_msg | route_update
  cleaner_id  UUID REFERENCES cleaners(id) ON DELETE SET NULL,
  client_id   UUID REFERENCES clients(id) ON DELETE CASCADE,
  message     TEXT,
  eta         TEXT,
  read        BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── ROW LEVEL SECURITY ───────────────────────────────────────────

ALTER TABLE clients       ENABLE ROW LEVEL SECURITY;
ALTER TABLE cleaners      ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE bookings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- Helper: is the current JWT the admin?
CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
  SELECT COALESCE(auth.jwt() ->> 'email', '') = 'clearbin12@gmail.com'
$$;

-- clients: owner sees own row; admin sees all
CREATE POLICY "clients_self"  ON clients FOR SELECT USING (auth.uid() = id);
CREATE POLICY "clients_self_update" ON clients FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "clients_insert" ON clients FOR INSERT WITH CHECK (auth.uid() = id);
CREATE POLICY "clients_admin" ON clients FOR ALL USING (is_admin());

-- cleaners: admin full access; anon/cleaner access via RPC only
CREATE POLICY "cleaners_admin" ON cleaners FOR ALL USING (is_admin());

-- jobs: clients see their own; admin sees all; cleaner access via RPC
CREATE POLICY "jobs_client"   ON jobs FOR SELECT USING (auth.uid() = client_id);
CREATE POLICY "jobs_admin"    ON jobs FOR ALL    USING (is_admin());

-- bookings: anon can INSERT (booking form); admin can do everything
CREATE POLICY "bookings_insert" ON bookings FOR INSERT WITH CHECK (TRUE);
CREATE POLICY "bookings_admin"  ON bookings FOR ALL    USING (is_admin());

-- notifications: clients see their own; anon can INSERT (cleaners post without auth)
CREATE POLICY "notif_client"    ON notifications FOR SELECT USING (auth.uid() = client_id);
CREATE POLICY "notif_insert"    ON notifications FOR INSERT WITH CHECK (TRUE);
CREATE POLICY "notif_admin"     ON notifications FOR ALL    USING (is_admin());
CREATE POLICY "notif_update_own" ON notifications FOR UPDATE USING (auth.uid() = client_id);

-- ── RPC FUNCTIONS ────────────────────────────────────────────────

-- Cleaner login: checks name+PIN without exposing the cleaners table
CREATE OR REPLACE FUNCTION authenticate_cleaner(p_name TEXT, p_pin TEXT)
RETURNS TABLE(id UUID, name TEXT, cities TEXT[], active BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  RETURN QUERY
  SELECT c.id, c.name, c.cities, c.active
  FROM   cleaners c
  WHERE  c.name ILIKE (split_part(p_name, ' ', 1) || '%')
  AND    c.pin    = p_pin
  AND    c.active = TRUE
  LIMIT 1;
END;
$$;
GRANT EXECUTE ON FUNCTION authenticate_cleaner TO anon;

-- Get today's jobs for a cleaner (with client contact info)
CREATE OR REPLACE FUNCTION get_cleaner_jobs(p_cleaner_id UUID, p_date DATE DEFAULT CURRENT_DATE)
RETURNS TABLE(
  id UUID, status TEXT, eta TEXT, admin_notes TEXT,
  plan TEXT, bins TEXT[], earnings NUMERIC,
  before_photo TEXT, after_photo TEXT,
  client_id UUID, client_name TEXT, client_phone TEXT,
  street TEXT, city TEXT, zip TEXT
)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  RETURN QUERY
  SELECT
    j.id, j.status, j.eta, j.admin_notes,
    j.plan, j.bins, j.earnings,
    j.before_photo, j.after_photo,
    j.client_id,
    (c.first_name || ' ' || c.last_name),
    c.phone,
    c.street, c.city, c.zip
  FROM jobs j
  LEFT JOIN clients c ON c.id = j.client_id
  WHERE j.cleaner_id = p_cleaner_id
  AND   j.scheduled_date = p_date
  ORDER BY j.created_at;
END;
$$;
GRANT EXECUTE ON FUNCTION get_cleaner_jobs TO anon;

-- Update job status (called by cleaner without Supabase Auth)
CREATE OR REPLACE FUNCTION update_job_status(p_job_id UUID, p_cleaner_id UUID, p_status TEXT, p_eta TEXT DEFAULT NULL)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE jobs
  SET    status = p_status,
         eta    = COALESCE(p_eta, eta)
  WHERE  id         = p_job_id
  AND    cleaner_id = p_cleaner_id;
END;
$$;
GRANT EXECUTE ON FUNCTION update_job_status TO anon;

-- Insert cleaner→client notification (cleaner has no Supabase Auth)
CREATE OR REPLACE FUNCTION insert_arrival_notification(
  p_cleaner_id UUID, p_client_id UUID, p_eta TEXT
)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  -- Clear previous on_way notifications for this pair
  DELETE FROM notifications
  WHERE  cleaner_id = p_cleaner_id
  AND    client_id  = p_client_id
  AND    type       = 'cleaner_on_way';

  INSERT INTO notifications (type, cleaner_id, client_id, message, eta)
  VALUES ('cleaner_on_way', p_cleaner_id, p_client_id, 'Your cleaner is on the way!', p_eta);
END;
$$;
GRANT EXECUTE ON FUNCTION insert_arrival_notification TO anon;

-- Admin: approve a booking (update status + activate client record)
CREATE OR REPLACE FUNCTION approve_booking(p_booking_id UUID)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE bookings SET status = 'approved' WHERE id = p_booking_id;
  UPDATE clients   SET status = 'active'
  WHERE  id = (SELECT client_id FROM bookings WHERE id = p_booking_id);
END;
$$;
GRANT EXECUTE ON FUNCTION approve_booking TO authenticated;

-- Admin: get all bookings (including those without a linked client yet)
CREATE OR REPLACE FUNCTION admin_get_bookings()
RETURNS TABLE(
  id UUID, status TEXT, first_name TEXT, last_name TEXT, email TEXT,
  phone TEXT, plan TEXT, city TEXT, zip TEXT, bins TEXT[],
  start_date DATE, notes TEXT, referral TEXT, created_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  RETURN QUERY SELECT
    b.id, b.status, b.first_name, b.last_name, b.email,
    b.phone, b.plan, b.city, b.zip, b.bins,
    b.start_date, b.notes, b.referral, b.created_at
  FROM bookings b ORDER BY b.created_at DESC;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_get_bookings TO authenticated;

-- Admin: get all clients
CREATE OR REPLACE FUNCTION admin_get_clients()
RETURNS TABLE(
  id UUID, first_name TEXT, last_name TEXT, phone TEXT,
  plan TEXT, city TEXT, zip TEXT, status TEXT, created_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  RETURN QUERY SELECT
    c.id, c.first_name, c.last_name, c.phone,
    c.plan, c.city, c.zip, c.status, c.created_at
  FROM clients c ORDER BY c.created_at DESC;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_get_clients TO authenticated;

-- Admin: get all cleaners (safe, no PINs)
CREATE OR REPLACE FUNCTION admin_get_cleaners()
RETURNS TABLE(id UUID, name TEXT, active BOOLEAN, cities TEXT[], created_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  RETURN QUERY SELECT c.id, c.name, c.active, c.cities, c.created_at FROM cleaners c ORDER BY c.name;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_get_cleaners TO authenticated;

-- Admin: toggle cleaner active/inactive
CREATE OR REPLACE FUNCTION admin_toggle_cleaner(p_cleaner_id UUID, p_active BOOLEAN)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  UPDATE cleaners SET active = p_active WHERE id = p_cleaner_id;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_toggle_cleaner TO authenticated;

-- Admin: add a new cleaner
CREATE OR REPLACE FUNCTION admin_add_cleaner(p_name TEXT, p_pin TEXT, p_cities TEXT[])
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_id UUID;
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  INSERT INTO cleaners (name, pin, cities) VALUES (p_name, p_pin, p_cities)
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_add_cleaner TO authenticated;

-- Admin: get today's route (all cleaners + their jobs)
CREATE OR REPLACE FUNCTION admin_get_route(p_date DATE DEFAULT CURRENT_DATE)
RETURNS TABLE(
  job_id UUID, cleaner_id UUID, cleaner_name TEXT,
  client_name TEXT, city TEXT, zip TEXT, plan TEXT,
  status TEXT, scheduled_date DATE, admin_notes TEXT
)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  RETURN QUERY
  SELECT j.id, j.cleaner_id, cl.name,
    (c.first_name || ' ' || c.last_name), c.city, c.zip, j.plan,
    j.status, j.scheduled_date, j.admin_notes
  FROM jobs j
  LEFT JOIN cleaners cl ON cl.id = j.cleaner_id
  LEFT JOIN clients  c  ON c.id  = j.client_id
  WHERE j.scheduled_date = p_date
  ORDER BY cl.name, j.created_at;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_get_route TO authenticated;

-- Admin: add a note to a job
CREATE OR REPLACE FUNCTION admin_set_job_note(p_job_id UUID, p_note TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT is_admin() THEN RAISE EXCEPTION 'Unauthorized'; END IF;
  UPDATE jobs SET admin_notes = p_note WHERE id = p_job_id;
END;
$$;
GRANT EXECUTE ON FUNCTION admin_set_job_note TO authenticated;

-- ── SEED DATA ────────────────────────────────────────────────────
-- Default cleaner roster (owner communicates PINs directly)
-- PINs: Marcus = 2748, Kim = 5561, Jordan = 9903
INSERT INTO cleaners (name, pin, active, cities) VALUES
  ('Marcus D.', '2748', TRUE,  ARRAY['Maple Grove', 'Medina']),
  ('Kim T.',    '5561', TRUE,  ARRAY['Plymouth']),
  ('Jordan R.', '9903', FALSE, ARRAY['Maple Grove', 'Plymouth', 'Medina'])
ON CONFLICT DO NOTHING;
