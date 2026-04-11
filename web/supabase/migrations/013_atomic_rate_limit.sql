-- Atomic rate limit increment — prevents race condition bypass
-- Returns the new count, or -1 if limit exceeded
CREATE OR REPLACE FUNCTION increment_chat_count(p_user_id UUID, p_limit INT)
RETURNS INT AS $$
DECLARE
  current_count INT;
  reset_date DATE;
BEGIN
  -- Lock the row to prevent concurrent updates
  SELECT chat_count_today, chat_count_reset_at::DATE
    INTO current_count, reset_date
    FROM profiles
    WHERE id = p_user_id
    FOR UPDATE;

  -- Reset if new day
  IF reset_date IS NULL OR reset_date < CURRENT_DATE THEN
    UPDATE profiles
      SET chat_count_today = 1, chat_count_reset_at = now()
      WHERE id = p_user_id;
    RETURN 1;
  END IF;

  -- Check limit
  IF current_count >= p_limit THEN
    RETURN -1;  -- Limit exceeded
  END IF;

  -- Increment
  UPDATE profiles
    SET chat_count_today = current_count + 1
    WHERE id = p_user_id;

  RETURN current_count + 1;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
