-- =============================================================================
-- 012: Security Hardening
-- Fixes: privilege escalation, field constraints, rate limit integrity
-- =============================================================================

-- ─── FIX #1: Prevent users from self-escalating tier/role ─────────────────────
-- The old policy allowed users to UPDATE any column on their own profile,
-- including tier and role. Replace with a restricted policy.

DROP POLICY IF EXISTS profiles_update ON profiles;

-- Users can update their own profile, but tier and role must stay unchanged
CREATE POLICY profiles_update_restricted ON profiles FOR UPDATE
  USING (auth.uid() = id)
  WITH CHECK (
    auth.uid() = id
    AND tier IS NOT DISTINCT FROM (SELECT p.tier FROM profiles p WHERE p.id = auth.uid())
    AND role IS NOT DISTINCT FROM (SELECT p.role FROM profiles p WHERE p.id = auth.uid())
  );

-- ─── FIX #2: Prevent profile self-deletion ────────────────────────────────────
CREATE POLICY profiles_no_delete ON profiles FOR DELETE USING (false);

-- ─── FIX #3: Constrain preferred_model to valid values ────────────────────────
ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_preferred_model_check;
ALTER TABLE profiles ADD CONSTRAINT profiles_preferred_model_check
  CHECK (preferred_model IN ('auto', 'claude', 'claude-opus', 'gpt', 'gpt-codex'));

-- ─── FIX #4: Add length constraints on user-input text fields ─────────────────
ALTER TABLE threat_reports DROP CONSTRAINT IF EXISTS threat_reports_title_length;
ALTER TABLE threat_reports ADD CONSTRAINT threat_reports_title_length CHECK (LENGTH(title) <= 500);

ALTER TABLE threat_reports DROP CONSTRAINT IF EXISTS threat_reports_content_length;
ALTER TABLE threat_reports ADD CONSTRAINT threat_reports_content_length CHECK (LENGTH(content) <= 100000);

ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_display_name_length;
ALTER TABLE profiles ADD CONSTRAINT profiles_display_name_length CHECK (LENGTH(display_name) <= 100);
